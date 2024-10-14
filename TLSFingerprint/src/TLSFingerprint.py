import boto3
import json
import random
import urllib
import ssl
import socket
import hashlib
import base64
from datetime import datetime

SOURCE_ARN = '<REPLACE-WITH-YOUR-SNI-RULEGROUP-ARN>'
DESTINATION_ARN = '<REPLACE-WITH-YOUR-TLS-FINGERPRINT-RULEGROUP-ARN>'

nf = boto3.client('network-firewall')

def gen_sid():
    return random.randint(0, 999999999)

def get_domains(arn):
    params = {"Type": "STATEFUL", "RuleGroupArn": arn}
    try:
        res = nf.describe_rule_group(**params)
        if 'RuleGroupResponse' in res:
            print("Found source rulegroup")
            domains = res['RuleGroup']['RulesSource']['RulesSourceList']['Targets']
            return domains
        else:
            print("ERROR: No matching Rule Group found")
    except Exception as e:
        print(f"Error: {str(e)}")
    return None
    
def fetch_cert(host, port=443):
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                der_cert = secure_sock.getpeercert(binary_form=True)
                cert = secure_sock.getpeercert()

        print(f"Hostname {host} verified successfully.")

        # Extract common name
        common_name = ''
        if cert and 'subject' in cert:
            subject = dict(x[0] for x in cert['subject'])
            common_name = subject.get('commonName', '')

        # Genrate SHA-1 fingerprint
        sha1_fingerprint = hashlib.sha1(der_cert).hexdigest()
        formatted_fingerprint = ':'.join(sha1_fingerprint[i:i+2] for i in range(0, len(sha1_fingerprint), 2))

        print(f'  Fetching from: {host}')
        print(f'    Subject Common Name: {common_name}')
        print(f'    Certificate Fingerprint (SHA-1): {formatted_fingerprint}')

        return {
            'subject': {'CN': common_name},
            'fingerprint': formatted_fingerprint
        }
    except ssl.CertificateError as e:
        print(f"Hostname verification failed for {host}: {e}")
        return None
    except Exception as e:
        print(f"Error fetching certificate for {host}: {str(e)}")
        return None

def update_rule_group(new_rule):
    params = {"Type": "STATEFUL", "RuleGroupArn": DESTINATION_ARN}
    try:
        res = nf.describe_rule_group(**params)
        if 'RuleGroupResponse' in res:
            print("Found destination rulegroup")
            res['RuleGroup']['RulesSource']['RulesString'] = new_rule
            res.pop('Capacity', None)
            res['RuleGroupName'] = res['RuleGroupResponse']['RuleGroupName']
            res['Description'] = res['RuleGroupResponse']['Description']
            res['Type'] = res['RuleGroupResponse']['Type']
            # Remove keys that can't be updated
            res.pop('ResponseMetadata', None)
            res.pop('Capacity', None)
            res.pop('RuleGroupResponse', None)

            print("Updating rules")
            result = nf.update_rule_group(**res)
            if result:
                print(f"Updated '{res['RuleGroupName']}'")
                return True
            else:
                print(f"Error updating '{res['RuleGroupName']}'...")
                return False
        else:
            print("No matching Rule Group found")
            return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def lambda_handler(event, context):
    if event.get('RequestType') == "Delete":
        return {'statusCode': 200, 'body': json.dumps('SUCCESS')}
    try:
        print(f"Fetch a list of domains from: {SOURCE_ARN}")
        domains = get_domains(SOURCE_ARN)
        
        if domains:
            print(f"Using a list of: {len(domains)} domains")
            new_rule = []
            new_rule.append(f'# This rule is automatically managed by a Lambda')
            new_rule.append(f'# Last updated: {datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")}')
            
            for domain in domains:
                f_cert = fetch_cert(domain, port=443)
                if f_cert:
                    new_rule.append(f'pass tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Allow https://{domain}/"; tls.cert_fingerprint; content:"{f_cert["fingerprint"]}"; sid:{gen_sid()}; rev:1;)')
                else:
                    new_rule.append(f'# ERROR: Unable to retrieve a fingerprint for: {domain}')

            new_rule.append(f'drop tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Drop all other TLS fingerprints"; tls.cert_fingerprint; content:!"{f_cert["fingerprint"]}"; sid:1; rev:1;)')
        
            update_success = update_rule_group('\n'.join(new_rule))
            
            if update_success:
                return {'statusCode': 200, 'body': json.dumps('SUCCESS')}
            else:
                print("Failed to update the rule group")
        else:
            print(f"Error fetching a list of domains from: {SOURCE_ARN}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")