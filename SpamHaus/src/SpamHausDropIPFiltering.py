import json
import urllib
import boto3
from datetime import datetime

# Constants
SPAM_HAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
RULE_GROUP_ARN = '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-RULE-GROUP>'

# Initialize AWS clients
networkfirewall = boto3.client('network-firewall')

def fetch_ips():
    print("Fetching the list of IP addresses...")
    try:
        with urllib.request.urlopen(SPAM_HAUS_DROP_URL) as response:
            data = response.read().decode('utf-8')
        
        list_of_ips = [line.split(" ;")[0] for line in data.splitlines() if line.strip() and line[0].isdigit()]
        print(f"Fetched {len(list_of_ips)} IP addresses...")
        return list_of_ips
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
    except Exception as e:
        print(f"Unexpected error fetching IP addresses: {str(e)}")
    return []

def update_rules(rule_group):
    params = rule_group.copy()
    params.pop('Capacity', None)
    params['RuleGroupName'] = params['RuleGroupResponse']['RuleGroupName']
    params['Type'] = params['RuleGroupResponse']['Type']
    # Remove keys that can't be updated
    params.pop('ResponseMetadata', None)
    params.pop('Capacity', None)
    params.pop('RuleGroupResponse', None)

    print("Updating rules...")
    try:
        res = networkfirewall.update_rule_group(**params)
        if res:
            print(f"Updated '{params['RuleGroupName']}'.")
            return True
        else:
            print(f"Error updating the rules for '{params['RuleGroupName']}'...")
            return False
    except Exception as e:
        print(f"Error updating rules: {str(e)}")
        return False

def create_rules(rule_group, rule_type):
    list_of_ips = fetch_ips()
    
    if not list_of_ips:
        print("No IP addresses fetched. Aborting rule creation.")
        return False

    rules = []
    rules.append(f"# Last updated: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}")
    rules.append(f"# Using a list of {len(list_of_ips)} IP addresses")

    for index, ip in enumerate(list_of_ips):
        rules.append(f"{rule_type} ip {ip} any -> any any (msg:\"{rule_type} emerging threats traffic from {ip}\"; rev:1; sid:55{index};)")
        rules.append(f"{rule_type} ip any any -> {ip} any (msg:\"{rule_type} emerging threats traffic to {ip}\"; rev:1; sid:66{index};)")

    rule_group['RuleGroup']['RulesSource']['RulesString'] = '\n'.join(rules)
    return update_rules(rule_group)

def lambda_handler(event, context):
    try:
        params = {"Type": "STATEFUL", "RuleGroupArn": RULE_GROUP_ARN}
        
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
        'statusCode': 200,
        'body': json.dumps('Function executed successfully')
    }