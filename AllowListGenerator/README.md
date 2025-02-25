# AWS Network Firewall Allow List Automation

## NATIVE FEATURE LAUNCH
NOTE: This feature is now natively apart of AWS Network Firewall.
- https://aws.amazon.com/about-aws/whats-new/2025/02/aws-network-firewall-automated-domain-lists/
- https://aws.amazon.com/blogs/security/from-log-analysis-to-rule-creation-how-aws-network-firewall-automates-domain-based-security-for-outbound-traffic/


This repository contains an AWS CloudFormation templates that help automate the allow list creation process for AWS Network Firewall based on network traffic logs. The solution analyzes the Network Firewall alert logs in Amazon S3, or CloudWatch logs, identifies the Server Name Indication (SNI) values associated with TLS traffic + the hostname associated with HTTP traffic and generates the corresponding allow rules in Suricata format. 

This solution is intended to help with building an allow list-based architecture for controlling outbound HTTP/TLS traffic from your workloads. It is not a fully automated solution, but rather a tool to surface the domains your workloads are reaching via HTTP/TLS, which can then be used to build out allow list rules. While this solution does not provide a fully automated allow list configuration, it aims to simplify the process of building and maintaining an allow list by providing visibility into the domains being accessed and generating rule recommendations based on the observed traffic patterns.

- If you store your AWS Network Firewall alert logs in Amazon S3, select the folder above named **s3-logs**.
- If you store your AWS Network Firewall alert logs in Amazon CloudWatch logs, select the folder above named **cloudwatch-logs**.

