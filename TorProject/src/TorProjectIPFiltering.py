import boto3
import urllib.request
from datetime import datetime

TOR_PROJECT_URL = "https://check.torproject.org/exit-addresses"
RULE_GROUP_ARN = "<Replace-with-your-stateful-rule-group-arn>"

networkfirewall = boto3.client('network-firewall')

def fetch_ips():
    print("Fetching the list of IP addresses...")
    try:
        with urllib.request.urlopen(TOR_PROJECT_URL) as response:
            data = response.read().decode('utf-8')
        
        ip_list = [line.split()[1] for line in data.splitlines() if line.startswith("ExitAddress ")]
        print(f"Fetched {len(ip_list)} IP addresses...")
        return ip_list
    except urllib.error.URLError as e:
        print(f"Error fetching IP addresses: {e}")
        return []

def update_rules(rule_group):
    params = rule_group.copy()
    print(params) # Debug line
    params['RuleGroupName'] = params['RuleGroupResponse']['RuleGroupName']
    params['Type'] = params['RuleGroupResponse']['Type']
    # Remove keys that can't be updated
    params.pop('ResponseMetadata', None)
    params.pop('Capacity', None)
    params.pop('RuleGroupResponse', None)
    
    print("Updating rules...")
    try:
        networkfirewall.update_rule_group(**params)
        print(f"Updated '{params['RuleGroupName']}'.")
    except Exception as e:
        print(f"Error updating the rules for '{params['RuleGroupName']}': {str(e)}")

def create_rules(rule_group, type_):
    ip_list = fetch_ips()

    rules_string = f"# Last updated: {datetime.utcnow().isoformat()}\n"
    rules_string += f"# Using a list of {len(ip_list)} IP addresses\n"
    
    for index, ip in enumerate(ip_list):
        rules_string += f"{type_} ip {ip} any -> any any (msg:\"{type_} emerging threats traffic from {ip}\"; rev:1; sid:55{index};)\n"
        rules_string += f"{type_} ip any any -> {ip} any (msg:\"{type_} emerging threats traffic to {ip}\"; rev:1; sid:66{index};)\n"

    rule_group['RuleGroup']['RulesSource']['RulesString'] = rules_string
    update_rules(rule_group)

def lambda_handler(event, context):
    try:
        params = {
            "Type": "STATEFUL", 
            "RuleGroupArn": RULE_GROUP_ARN
        }
        
        print("Searching for Rule Groups...")
        res = networkfirewall.describe_rule_group(**params)
        if 'RuleGroupResponse' in res:
            print("Found Rule Group...")
            create_rules(res, "drop")
        else:
            print("ERROR: No matching Rule Group found...")
    except Exception as e:
        print(f"Error: {str(e)}")

    return {
        'statusCode': 200,
        'body': 'Function executed successfully'
    }
