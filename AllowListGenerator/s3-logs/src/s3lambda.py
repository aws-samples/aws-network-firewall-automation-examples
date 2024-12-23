import boto3
import gzip
import json
import os
import base64
import datetime
import math
from collections import defaultdict

ddb = boto3.client("dynamodb")
nfw = boto3.client("network-firewall")
ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
DDB_TABLE_NAME = os.getenv("DDB_TABLE_NAME")
RULE_GROUP_ARN = os.getenv("RULE_GROUP_ARN")
WILDCARD_DOMAIN_MINIMUM = int(os.getenv("WILDCARD_DOMAIN_MINIMUM"))
MAX_RULES = int(os.getenv("MAX_RULES"))
RULE_SID_PREFIX = int(os.getenv("RULE_SID_PREFIX"))
ALERT_MESSAGE = os.getenv("ALERT_MESSAGE")
RULES_BUCKET_NAME = os.getenv("RULES_BUCKET_NAME")

ALERT_TEMPLATE_TLS = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"{message} unique_clients: {clients}, total_hits:{requests}"; tls.sni; content:"{hostname}"; startswith; nocase; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'
PASS_TEMPLATE_TLS = 'pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"{hostname}"; startswith; nocase; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'

ALERT_TEMPLATE_HTTP = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"{message}  unique_clients: {clients}, total_hits:{requests}"; http.host; content:"{hostname}"; startswith; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'
PASS_TEMPLATE_HTTP = 'pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"{hostname}"; startswith; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'

def get_hostname_stats() -> dict:
    print("Retrieving hostname stats from DynamoDB...")
    hostname_stats = {}
    result = ddb.scan(
        TableName=DDB_TABLE_NAME,
        ProjectionExpression="Hostname, Protocol, #SourceIPs, #RequestsToDomain, #UniqueSourceIPCount, #LastUpdatedTimestamp, #InstanceIDs",
        ExpressionAttributeNames={
            "#SourceIPs": "Source IPs",
            "#RequestsToDomain": "Requests to Domain",
            "#UniqueSourceIPCount": "Unique Source IP Count",
            "#LastUpdatedTimestamp": "Last Updated Timestamp",
            "#InstanceIDs": "Instance IDs"
        }
    )
    for item in result["Items"]:
        hostname = item["Hostname"]["S"]
        protocol = item["Protocol"]["S"]
        stats = {
            "Source IPs": set(item["Source IPs"]["SS"]),
            "Requests to Domain": int(item.get("Requests to Domain", {}).get("N", 0)),
            "Unique Source IP Count": len(set(item["Source IPs"]["SS"])),
            "Last Updated Timestamp": item["Last Updated Timestamp"]["N"],
            "Instance IDs": set(item.get("Instance IDs", {}).get("SS", []))
        }
        hostname_stats[(hostname, protocol)] = stats

    print("Retrieved hostname stats from DynamoDB.")
    return hostname_stats

def process_logs(log_data):
    print("Processing log data...")
    # Split the log data into individual log entries
    log_entries = log_data.strip().split('\n')

    # Process each log entry
    for log_entry in log_entries:
        if log_entry:
            log_data = json.loads(log_entry)
            print(f"Processing log entry: {log_entry}")

            if "event" in log_data and "app_proto" in log_data["event"]:
                if log_data["event"]["app_proto"] in ["tls", "http"]:
                    print("Valid TLS or HTTP log entry. Processing...")
                    process_alert_log(log_data)
                else:
                    print(f"Skipping log entry with unsupported protocol: {log_data['event']['app_proto']}")
            else:
                print(f"Skipping log entry without 'app_proto' field: {log_entry}")

def process_alert_log(alert_json) -> None:
    source_ip = alert_json["event"]["src_ip"]
    protocol = alert_json["event"]["app_proto"]
    unix_timestamp = str(alert_json["event_timestamp"])

    if protocol == "tls":
        hostname = alert_json["event"]["tls"].get("sni", None)
    elif protocol == "http":
        hostname = alert_json["event"]["http"].get("hostname", None)
    else:
        hostname = None

    if not hostname:
        print("Hostname not found")
        return

    print(f"Processing log entry for {hostname} ({protocol})")

    instance_id = get_instance_id_from_ip(source_ip)  # Get instance ID from Source IP

    # Update: ADD Source IPs and Instance IDs
    update_expression = "ADD #SourceIPs :source_ips"
    expression_attribute_values = {":source_ips": {"SS": [source_ip]}}

    if instance_id:
        update_expression += ", #InstanceIDs :instance_id"
        expression_attribute_values[":instance_id"] = {"SS": [instance_id]}

    response = ddb.update_item(
        TableName=DDB_TABLE_NAME,
        Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
        UpdateExpression=update_expression,
        ExpressionAttributeNames={
            "#SourceIPs": "Source IPs",
            "#InstanceIDs": "Instance IDs"
        },
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues="ALL_NEW"
    )
    print(f"DynamoDB update response: {response}")

    if "Attributes" in response:
        source_ips = set(response["Attributes"].get("Source IPs", {}).get("SS", []))
        last_updated_timestamp = response["Attributes"].get("Last Updated Timestamp", {}).get("N", unix_timestamp)

        if "Requests to Domain" not in response["Attributes"]:
            print(f"Creating new 'Requests to Domain' entry for {hostname}, {protocol}")
            ddb.update_item(
                TableName=DDB_TABLE_NAME,
                Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
                UpdateExpression="SET #RequestsToDomain = :requests, #LastUpdatedTimestamp = :timestamp",
                ExpressionAttributeNames={
                    "#RequestsToDomain": "Requests to Domain",
                    "#LastUpdatedTimestamp": "Last Updated Timestamp",
                },
                ExpressionAttributeValues={
                    ":requests": {"N": "1"},
                    ":timestamp": {"N": unix_timestamp},
                },
            )
        else:
            existing_requests = int(response["Attributes"]["Requests to Domain"]["N"])
            if source_ip not in source_ips or str(unix_timestamp) != last_updated_timestamp:
                new_requests = existing_requests + 1
                print(f"Updating 'Requests to Domain' for {hostname}, {protocol} to {new_requests}")
                ddb.update_item(
                    TableName=DDB_TABLE_NAME,
                    Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
                    UpdateExpression="SET #RequestsToDomain = :requests, #LastUpdatedTimestamp = :timestamp ADD #SourceIPs :source_ip",
                    ExpressionAttributeNames={
                        "#RequestsToDomain": "Requests to Domain",
                        "#LastUpdatedTimestamp": "Last Updated Timestamp",
                        "#SourceIPs": "Source IPs"
                    },
                    ExpressionAttributeValues={
                        ":requests": {"N": str(new_requests)},
                        ":timestamp": {"N": unix_timestamp},
                        ":source_ip": {"SS": [source_ip]}
                    },
                )
            else:
                print(f"Skipping 'Requests to Domain' update for {hostname}, {protocol} (duplicate log)")

        print(f"Updating 'Unique Source IP Count' for {hostname}, {protocol}")
        ddb.update_item(
            TableName=DDB_TABLE_NAME,
            Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
            UpdateExpression="SET #UniqueSourceIPCount = :workloads",
            ExpressionAttributeNames={
                "#UniqueSourceIPCount": "Unique Source IP Count"
            },
            ExpressionAttributeValues={":workloads": {"N": str(len(source_ips))}},
        )

def get_instance_id_from_ip(source_ip):
    try:
        response = ec2.describe_instances(Filters=[
            {
                'Name': 'private-ip-address',
                'Values': [source_ip]
            }
        ])
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                return instance['InstanceId']
    except Exception as e:
        print(f"Error getting instance ID for IP {source_ip}: {e}")
    return None


def lambda_handler(event, context):
    print("Lambda function invoked.")
    s3_client = boto3.client('s3')

    # Check if the event is from S3 or EventBridge
    if "Records" in event and event["Records"][0]["eventSource"] == "aws:s3":
        print("Processing S3 event...")
        # S3 event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']

        # Download the log file from S3
        print(f"Downloading log file from S3 bucket: {bucket_name}, key: {key}")
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        log_data = response['Body'].read()

        # Decompress the gzipped log file
        print("Decompressing log file...")
        log_data = gzip.decompress(log_data)

        # Process the log data
        process_logs(log_data.decode('utf-8'))
    else:
        print("Processing EventBridge event...")
        update_rule_group(event)


def update_rule_group(event) -> None:
    print("Updating AWS Network Firewall rule group...")
    # Get hostname stats from DynamoDB table
    hostname_stats = get_hostname_stats()

    if not hostname_stats:
        print("No hostname logs have been processed")
        return

    # Generate a list of Suricata rules from stats
    sorted_hostnames = sorted(hostname_stats.keys(), key=lambda x: hostname_stats[x]['Requests to Domain'], reverse=True)
    top_hostnames = sorted_hostnames[:MAX_RULES]

    # Determine max length of SID so we can pad with zeros.
    sid_width = math.ceil(math.log10(MAX_RULES))

    i = 0
    rules = []

    # Add TLS wildcard rules
    rules.append("# TLS Wildcard Rules")

    # Process TLS wildcard rules
    tls_domain_counts = defaultdict(int)
    tls_domain_stats = defaultdict(lambda: {"Source IPs": set(), "Requests to Domain": 0})
    for hostname, protocol in top_hostnames:
        if protocol == "tls":
            domain = ".".join(hostname.split(".")[-2:])
            tls_domain_counts[domain] += 1
            tls_domain_stats[domain]["Source IPs"].update(hostname_stats[(hostname, protocol)]["Source IPs"])
            tls_domain_stats[domain]["Requests to Domain"] += hostname_stats[(hostname, protocol)]["Requests to Domain"]

    for domain, count in sorted(tls_domain_counts.items(), key=lambda x: x[1], reverse=True):
        if count >= WILDCARD_DOMAIN_MINIMUM:
            clients = len(tls_domain_stats[domain]["Source IPs"])
            requests = tls_domain_stats[domain]["Requests to Domain"]

            # TLS Alert rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"{ALERT_MESSAGE},  unique_clients: {clients}, total_hits:{requests}"; tls.sni; content:\".{domain}\"; endswith; nocase; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)'
            rules.append(wildcard_rule)
            print(f"Added TLS wildcard alert rule: {wildcard_rule}")
            i += 1

            # TLS Pass rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f"pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:\".{domain}\"; endswith; nocase; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)"
            rules.append(wildcard_rule)
            print(f"Added TLS wildcard pass rule: {wildcard_rule}")
            i += 1

    # Add HTTP wildcard rules
    rules.extend(["", ""])
    rules.append("# HTTP Wildcard Rules")

    # Process HTTP wildcard rules
    http_domain_counts = defaultdict(int)
    http_domain_stats = defaultdict(lambda: {"Source IPs": set(), "Requests to Domain": 0})
    for hostname, protocol in top_hostnames:
        if protocol == "http":
            domain = ".".join(hostname.split(".")[-2:])
            http_domain_counts[domain] += 1
            http_domain_stats[domain]["Source IPs"].update(hostname_stats[(hostname, protocol)]["Source IPs"])
            http_domain_stats[domain]["Requests to Domain"] += hostname_stats[(hostname, protocol)]["Requests to Domain"]

    for domain, count in sorted(http_domain_counts.items(), key=lambda x: x[1], reverse=True):
        if count >= WILDCARD_DOMAIN_MINIMUM:
            clients = len(http_domain_stats[domain]["Source IPs"])
            requests = http_domain_stats[domain]["Requests to Domain"]

            # HTTP Alert rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"{ALERT_MESSAGE},  unique_clients: {clients}, total_hits:{requests}"; http.host; content:\".{domain}\"; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)'
            rules.append(wildcard_rule)
            print(f"Added HTTP wildcard alert rule: {wildcard_rule}")
            i += 1

            # HTTP Pass rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f"pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:\".{domain}\"; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)"
            rules.append(wildcard_rule)

    # Add TLS specific rules
    rules.extend(["", ""])
    rules.append("# TLS Specific Rules")

    for hostname, protocol in sorted(top_hostnames, key=lambda x: hostname_stats[x]['Requests to Domain'], reverse=True):
        if protocol == "tls":
            stats = hostname_stats[(hostname, protocol)]

            sid = str(i).zfill(sid_width)
            params = {
                "hostname": hostname,
                "clients": stats["Unique Source IP Count"],
                "requests": stats["Requests to Domain"],
                "sid": f"{RULE_SID_PREFIX}{sid}",
                "message": ALERT_MESSAGE,
            }
            tls_alert_rule = ALERT_TEMPLATE_TLS.format(**params)
            rules.append(tls_alert_rule)
            i += 1

            sid = str(i).zfill(sid_width)
            params = {
                "hostname": hostname,
                "clients": stats["Unique Source IP Count"],
                "requests": stats["Requests to Domain"],
                "sid": f"{RULE_SID_PREFIX}{sid}",
            }
            tls_pass_rule = PASS_TEMPLATE_TLS.format(**params)
            rules.append(tls_pass_rule)
            i += 1

    # Add HTTP specific rules
    rules.extend(["", ""])
    rules.append("# HTTP Specific Rules")

    for hostname, protocol in sorted(top_hostnames, key=lambda x: hostname_stats[x]['Requests to Domain'], reverse=True):
        if protocol == "http":
            stats = hostname_stats[(hostname, protocol)]

            sid = str(i).zfill(sid_width)
            params = {
                "hostname": hostname,
                "clients": stats["Unique Source IP Count"],
                "requests": stats["Requests to Domain"],
                "sid": f"{RULE_SID_PREFIX}{sid}",
                "message": ALERT_MESSAGE,
            }
            http_alert_rule = ALERT_TEMPLATE_HTTP.format(**params)
            rules.append(http_alert_rule)
            i += 1

            sid = str(i).zfill(sid_width)
            params = {
                "hostname": hostname,
                "clients": stats["Unique Source IP Count"],
                "requests": stats["Requests to Domain"],
                "sid": f"{RULE_SID_PREFIX}{sid}",
            }
            http_pass_rule = PASS_TEMPLATE_HTTP.format(**params)
            rules.append(http_pass_rule)
            i += 1


    # Join the rules into a single string
    rule_string = "\n".join(rules)

    # Get UpdateToken so we can update the rule group
    rule_group = nfw.describe_rule_group(RuleGroupArn=RULE_GROUP_ARN, Type="STATEFUL")

    # Update the rule group with the entire rule string
    params = {
        "UpdateToken": rule_group["UpdateToken"],
        "RuleGroupArn": RULE_GROUP_ARN,
        "RuleGroup": {
            "RulesSource": {"RulesString": rule_string},
            "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
        },
        "Type": "STATEFUL",
        "EncryptionConfiguration": {"Type": "AWS_OWNED_KMS_KEY"},
    }
    try:
        nfw.update_rule_group(**params)
        print("Rule group updated successfully.")
    except Exception as e:
        print(f"Error updating rule group: {e}")

    # Write rules to S3
    try:
        s3.put_object(
            Bucket=RULES_BUCKET_NAME,
            Key='rules.txt',
            Body=rule_string.encode('utf-8')
        )
        print("Rules written to S3 successfully.")
    except Exception as e:
        print(f"Error writing rules to S3: {e}")