import boto3, json, os, base64, gzip, datetime, math
from collections import defaultdict

ddb = boto3.client("dynamodb")
nfw = boto3.client("network-firewall")
ec2 = boto3.client("ec2")
cw = boto3.client("cloudwatch")
DDB_TABLE_NAME = os.getenv("DDB_TABLE_NAME")
RULE_GROUP_ARN = os.getenv("RULE_GROUP_ARN")
WILDCARD_DOMAIN_MINIMUM = int(os.getenv("WILDCARD_DOMAIN_MINIMUM"))
MAX_RULES = int(os.getenv("MAX_RULES"))
RULE_SID_PREFIX = int(os.getenv("RULE_SID_PREFIX"))
ALERT_MESSAGE = os.getenv("ALERT_MESSAGE")
CW_METRICS_NAMESPACE = os.getenv("CW_METRICS_NAMESPACE")

ALERT_TEMPLATE_TLS = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"{message} unique_clients: {clients}, total_hits:{requests}"; tls.sni; content:"{hostname}"; startswith; nocase; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'
PASS_TEMPLATE_TLS = 'pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"{hostname}"; startswith; nocase; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'

ALERT_TEMPLATE_HTTP = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"{message}  unique_clients: {clients}, total_hits:{requests}"; http.host; content:"{hostname}"; startswith; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'
PASS_TEMPLATE_HTTP = 'pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"{hostname}"; startswith; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{sid};)'

def get_hostname_stats() -> dict:
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

    return hostname_stats

def update_metrics(alert_json) -> None:
    protocol = alert_json["event"]["app_proto"]
    timestamp = alert_json["event"]["timestamp"]
    timestamp_dt = datetime.datetime.fromisoformat(timestamp)
    firewall_name = alert_json["firewall_name"]

    if protocol == "tls":
        hostname = alert_json["event"]["tls"].get("sni", None)
    elif protocol == "http":
        hostname = alert_json["event"]["http"].get("hostname", None)
    else:
        print(f"Unknown protocol: {protocol}")
        return

    if not hostname:
        print("Hostname not found")
        return

    metrics = [
        {
            "MetricName": "Flows",
            "Dimensions": [
                {
                    "Name": "FirewallName",
                    "Value": firewall_name
                },
                {
                    "Name": "Domain",
                    "Value": hostname
                },
                {
                    "Name": "Protocol",
                    "Value": protocol
                }
            ],
            "Value": 1,
            "Timestamp": timestamp_dt,
            "Unit": "Count",
            "StorageResolution": 60
        }
    ]
    cw.put_metric_data(Namespace=CW_METRICS_NAMESPACE, MetricData=metrics)

def process_alert_log(alert_json) -> None:
    source_ip = alert_json["event"]["src_ip"]
    protocol = alert_json["event"]["app_proto"]
    unix_timestamp = str(alert_json["event_timestamp"])

    if protocol == "tls":
        hostname = alert_json["event"]["tls"].get("sni", None)
    elif protocol == "http":
        hostname = alert_json["event"]["http"].get("hostname", None)
    else:
        print(f"Unknown protocol: {protocol}")
        return

    if not hostname:
        print("Hostname not found")
        return

    instance_id = get_instance_id_from_ip(source_ip)  # Get instance ID from Source IP

    # First update: ADD Source IPs
    response = ddb.update_item(
        TableName=DDB_TABLE_NAME,
        Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
        UpdateExpression="ADD #SourceIPs :source_ips",
        ExpressionAttributeNames={
            "#SourceIPs": "Source IPs",
        },
        ExpressionAttributeValues={
            ":source_ips": {"SS": [source_ip]},
        },
        ReturnValues="ALL_NEW"
    )

    # Second update: ADD Instance IDs
    if instance_id:
        ddb.update_item(
            TableName=DDB_TABLE_NAME,
            Key={"Hostname": {"S": hostname}, "Protocol": {"S": protocol}},
            UpdateExpression="ADD #InstanceIDs :instance_id",
            ExpressionAttributeNames={
                "#InstanceIDs": "Instance IDs"
            },
            ExpressionAttributeValues={
                ":instance_id": {"SS": [instance_id]}
            }
        )

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

def process_logs(event) -> None:
    data = event["awslogs"]["data"]
    decoded_event = json.loads(gzip.decompress(base64.b64decode(data)))
    for log_event in decoded_event["logEvents"]:
        body = log_event["message"]
        alert_json = json.loads(body)
        process_alert_log(alert_json)
        update_metrics(alert_json)
        
def update_rule_group(event) -> None:
    # Get hostname stats from DynamoDB table
    hostname_stats = get_hostname_stats()

    if not hostname_stats:
        print("no hostname logs have been processed")
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
            i += 1

            # TLS Pass rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f"pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:\".{domain}\"; endswith; nocase; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)"
            rules.append(wildcard_rule)
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
            i += 1

            # HTTP Pass rule
            sid = str(i).zfill(sid_width)
            wildcard_rule = f"pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:\".{domain}\"; endswith; flow:to_server; metadata: unique_clients,{clients},total_hits,{requests}; sid:{RULE_SID_PREFIX}{sid};)"
            rules.append(wildcard_rule)
            i += 1

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
    nfw.update_rule_group(**params)
    
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

def handler(event, context) -> None:
    if "awslogs" in event:
        # CloudWatch Logs
        print("Processing CloudWatch Logs event")
        process_logs(event)
    else:
        # EventBridge
        print("Processing EventBridge event")
        update_rule_group(event)
