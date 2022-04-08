# (c) 2021 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
# This AWS Content is provided subject to the terms of the AWS Customer
# Agreement available at https://aws.amazon.com/agreement/ or other written
# agreement between Customer and Amazon Web Services, Inc.
# Author : vramaam@amazon.com

import json
import boto3
import os
import logging
import urllib.parse
from io import BytesIO
import gzip
import base64
import requests
from botocore.exceptions import ClientError
from ipaddress import ip_network, ip_address

import urllib3
import json
http = urllib3.PoolManager()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3 = boto3.client('s3')


def lambda_handler(event, context):

    logger.info('Raw Lambda event:')
    logger.info(event)
    
    slackEndpoint= get_secret ()
    logger.debug("Retrived slackEndpoint from ASM")

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    logger.info("bucket:"+bucket )
    logger.info("key:"+key )
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        logger.info('S3 object triggered this lambda:')
        logger.info(response['ContentType'])
        bytestream = BytesIO(response['Body'].read())
        got_text = gzip.GzipFile(mode='rb', fileobj=bytestream).read().decode('utf-8')
        logger.info(got_text)
        post_slack_Message (event, context, slackEndpoint, convertText2Json(got_text))
        return response['ContentType']
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e


def convertText2Json (rawJasonFormattedText):
    nfwalerts = []
    for line in rawJasonFormattedText.splitlines():
        nfwAlert = json.loads(line)
        if (isPublishable(nfwAlert)):
            nfwalerts.append(nfwAlert)
    if not nfwalerts:
        return
    return json.dumps (nfwalerts)


def isPublishable (nfwAlert):
    # Liberal filter 
    srcCidr = os.environ['srcCidr']
    destCidr = os.environ['destCidr']

    srcCheckReqd = (len(srcCidr) != 0)
    destCheckReqd = (len(destCidr) != 0) 

    if len(srcCidr) == 0 and len(destCidr)== 0 :
        return True
    
    srcCondition = os.environ['srcCondition']
    destCondition = os.environ['destCondition']

    srcIP = nfwAlert["event"]["src_ip"]
    destIP = nfwAlert["event"]["dest_ip"]
    
    includeSrc = True
    if (srcCheckReqd):
        net = ip_network(srcCidr)
        logger.info("Check-Src:"+str (ip_address(srcIP) in net) )
        if (not (ip_address(srcIP) in net) and (srcCondition == "include")):
            includeSrc =  False
        if ( (ip_address(srcIP) in net) and (srcCondition != "include")):
            logger.info("srcCheckReqd:"+str (srcCheckReqd) )
            includeSrc = False     
      
    includeDest = True
    if (destCheckReqd):
        net = ip_network(destCidr)
        logger.info("Check-Dest:"+str (ip_address(destIP) in net) )
        if (not (ip_address(destIP) in net) and (destCondition == "include")):
            includeDest =  False
        if ( (ip_address(destIP) in net) and (destCondition != "include")):
            includeDest = False   

    return includeSrc or includeDest


def get_secret():

    secret_name = os.environ['slackSecretName']
    region_name = os.environ['secretRegion']

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print (e)
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secret_dict  = json.loads(secret)
            webhookUrl= secret_dict['webhookUrl']
            return webhookUrl
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
   

    
def post_slack_Message (event, context, url, message):
    
    if  not message :
        logger.info ("Slack Message body is empty, No message will be published.")
        return
    SLACK_CHANNEL = os.environ['slackChannel']
    SLACK_USER = os.environ['slackUser']
    msg = {
        "channel": SLACK_CHANNEL,
        "username": SLACK_USER,
        "text": message,
        "icon_emoji": ""
    }
    
    encoded_msg = json.dumps(msg).encode('utf-8')
    resp = http.request('POST',url, body=encoded_msg)
    print({
        "message": message, 
        "status_code": resp.status, 
        "response": resp.data
    })
