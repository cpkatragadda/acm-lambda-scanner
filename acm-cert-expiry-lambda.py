import json
import boto3
import os
from datetime import datetime, timedelta, timezone
import logging
from botocore.exceptions import ClientError

# Initiate logger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# -------------------------------------------
# setup global data
# -------------------------------------------
utc = timezone.utc

# make today timezone aware
today = datetime.now().replace(tzinfo=utc)

# set up time window for alert - default to 90 if its missing
if os.environ.get('EXPIRY_DAYS') is None:
    logger.info('No value found for EXPIRY_DAYS from Environment, Using default 90 days')
    expiry_days = 90
else:
    expiry_days = int(os.environ['EXPIRY_DAYS'])
    logger.info(os.environ['EXPIRY_DAYS'])
expiry_window = today + timedelta(days = expiry_days)


def lambda_handler(event, context):
    print('in lambda handler')
    response = handle_multiple_certs(event, context)
    
    return {
        'statusCode': 200,
        'body': response 
    }
    print('return')


def handle_multiple_certs(event, context_arn):
    cert_client = boto3.client('acm')
    print('in handle multiple certs')
    cert_list = json.loads(get_expiring_cert_arns())
    
    if cert_list is None:
        response = 'No certificates are expiring within ' + str(expiry_days) + ' days.'
        print('No certs found')
    else:
        response = 'The following certificates are expiring within ' + str(expiry_days) + ' days: \n'

        # loop through the cert list and pull out certs that are expiring within the expiry window
        for csl in cert_list:
            cert_arn = json.dumps(csl['Dimensions'][0]['Value']).replace('\"', '')
            cert_details = cert_client.describe_certificate(CertificateArn=cert_arn)

            if cert_details['Certificate']['NotAfter'] < expiry_window:
                current_cert = 'Domain:' + cert_details['Certificate']['DomainName'] + ' (' + cert_details['Certificate']['CertificateArn'] + '), \n'


                # This is the text going into the SNS notification
                response = response + current_cert
                
    # if there's an SNS topic, publish a notification to it
    if os.environ.get('SNS_TOPIC_ARN') is not None:
        sns_client = boto3.client('sns')
        response = sns_client.publish(TopicArn=os.environ['SNS_TOPIC_ARN'], Message=response.rstrip(', \n'), Subject='Certificate Expiration Notification')

    return response


def get_expiring_cert_arns():
    cert_list = []

    # Initialize CloudWatch client
    cloudwatch = boto3.client('cloudwatch')
    
    paginator = cloudwatch.get_paginator('list_metrics')

    for response in paginator.paginate(
        MetricName='DaysToExpiry',
        Namespace='AWS/CertificateManager',
        Dimensions=[{'Name': 'CertificateArn'}],):
            cert_list = cert_list + (response['Metrics'])

    # return all certs that are expiring according to CW
    return json.dumps(cert_list)
event = []
context = [{'invoked_function_arn': 'test'}]
lambda_handler(event, context)