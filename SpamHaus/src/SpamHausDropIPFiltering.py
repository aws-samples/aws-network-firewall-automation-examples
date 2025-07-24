import json
import urllib.request
import boto3
from datetime import datetime

# Configuration - adjust these values based on your setup
THREAT_INTEL_URL = "https://www.spamhaus.org/drop/drop.txt"  # SpamHaus DROP list
RULE_GROUP_ARN = '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-RULE-GROUP>'

# SID ranges for Suricata rules - adjust these to avoid conflicts with other
# rule sources. Each IP gets two rules: one for traffic FROM the IP, one for
# traffic TO the IP
SID_PREFIX_FROM = 10000  # SIDs for traffic FROM blocked IPs (10000-19999 range)
SID_PREFIX_TO = 15000    # SIDs for traffic TO blocked IPs (15000-19999 range)

# Rule message configuration
RULE_MESSAGE_PREFIX = "SpamHaus blocked"  # Customize this for your organization

# Rule capacity management - adjust RULE_GROUP_CAPACITY based on your Network
# Firewall rule group capacity. Valid range: 100-30000 (AWS Network Firewall limits)
RULE_GROUP_CAPACITY = 5000  # Total rule capacity of your rule group
# Each IP creates 2 rules (see rule generation below): one for inbound traffic,
# one for outbound traffic
MAX_RESULTS = RULE_GROUP_CAPACITY // 2  # 3000 ÷ 2 = 1500 IPs maximum

# Initialize AWS clients
networkfirewall = boto3.client('network-firewall')


def fetch_ips():
    print("Fetching the list of IP addresses...")
    try:
        with urllib.request.urlopen(THREAT_INTEL_URL, timeout=30) as response:
            data = response.read().decode('utf-8')
        
        list_of_ips = [
            line.split(" ;")[0] for line in data.splitlines() 
            if line.strip() and line.strip()[0].isdigit()
        ]
        print(f"Fetched {len(list_of_ips)} IP addresses...")
        return list_of_ips
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
    except Exception as e:
        print(f"Unexpected error fetching IP addresses: {str(e)}")
    return []


def update_rules(rule_group, rules_string):
    rule_group_name = rule_group["RuleGroupResponse"]["RuleGroupName"]
    
    print("Updating rules...")
    try:
        # Use UpdateToken from the describe_rule_group response for safe updates
        update_params = {
            "UpdateToken": rule_group["UpdateToken"],
            "RuleGroupArn": RULE_GROUP_ARN,
            "RuleGroup": {
                "RulesSource": {"RulesString": rules_string}
            },
            "Type": "STATEFUL"
        }
        
        res = networkfirewall.update_rule_group(**update_params)
        if res:
            print(f"Updated '{rule_group_name}'.")
            return True
        else:
            print(f"Error updating the rules for '{rule_group_name}'...")
            return False
    except Exception as e:
        if 'InvalidToken' in str(e):
            print(f"UpdateToken conflict for '{rule_group_name}': {str(e)}")
            print("Rule group may have been updated by another process")
            return False
        else:
            print(f"Error updating rules for '{rule_group_name}': {str(e)}")
            return False


def generate_ip_rule(rule_type, ip, direction, message, sid):
    if direction == "from":
        template = ('{rule_type} ip {ip} any -> any any '
                   '(msg:"{message} traffic from {ip}"; rev:1; sid:{sid};)')
    else:
        template = ('{rule_type} ip any any -> {ip} any '
                   '(msg:"{message} traffic to {ip}"; rev:1; sid:{sid};)')
    
    return template.format(
        rule_type=rule_type,
        ip=ip,
        message=message,
        # Format SID as 4-digit number with leading zeros (e.g., 0001, 0123, 1000)
        sid=f"{sid:04d}"
    )


def create_rules(rule_group, rule_type):
    list_of_ips = fetch_ips()
    
    if not list_of_ips:
        print("No IP addresses fetched. Aborting rule creation.")
        return False

    # Limit results to stay within rule capacity
    original_count = len(list_of_ips)
    list_of_ips = list_of_ips[:MAX_RESULTS]
    was_truncated = original_count > MAX_RESULTS

    rules = []
    timestamp = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    rules.append(f"# Last updated: {timestamp}")
    rules.append(f"# Processing {len(list_of_ips)} of {original_count} "
                f"IP addresses (limit: {MAX_RESULTS})")
    if was_truncated:
        rules.append(f"# WARNING: IP list truncated from {original_count} to "
                    f"{MAX_RESULTS} due to rule capacity limits")

    for index, ip in enumerate(list_of_ips):
        rule_from = generate_ip_rule(
            rule_type,
            ip,
            "from",
            RULE_MESSAGE_PREFIX,
            SID_PREFIX_FROM + index
        )
        rule_to = generate_ip_rule(
            rule_type,
            ip,
            "to",
            RULE_MESSAGE_PREFIX,
            SID_PREFIX_TO + index
        )
        rules.append(rule_from)
        rules.append(rule_to)

    rules_string = '\n'.join(rules)
    return update_rules(rule_group, rules_string)


def lambda_handler(event, context):
    try:
        params = {
            "Type": "STATEFUL", 
            "RuleGroupArn": RULE_GROUP_ARN
        }
        
        print("Searching Rule Groups for 'SpamHausIPList'...")
        res = networkfirewall.describe_rule_group(**params)

        if 'RuleGroupResponse' in res:
            print("Found Rule Group...")
            success = create_rules(res, "drop")
            if success:
                print("Rule Group update successful")
            else:
                print("Rule Group update failed")
        else:
            print("ERROR: No matching Rule Group found...")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    return {
        "statusCode": 200,
        "body": json.dumps("Function executed successfully")
    }