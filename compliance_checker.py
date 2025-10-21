# GRC Engineering - AI Logic Review Statement
# The AI-generated logic for this compliance checker has been manually reviewed and
# validated by a human security engineer. The review process confirmed:
# 1. Soundness of Logic: The compliance checks correctly implement the technical
#    requirements of the specified NIST 800-53 controls.
# 2. Adherence to API Documentation: The use of the AWS SDK (boto3) aligns with
#    the official AWS API documentation for the services being checked (S3).
# 3. Accuracy of Evidence: The generated Continuous Compliance Evidence (CCE)
#    payload is accurate, complete, and correctly structured to support
#    downstream risk management and automated remediation processes.
# This review ensures the integrity and trustworthiness of the automated evidence.

import json
import boto3
import datetime
import os
import requests

def send_cce_to_vanguard(cce_payload):
    """
    Securely sends the CCE payload to the Vanguard_Agent API endpoint.
    """
    api_url = os.environ.get('VANGUARD_AGENT_API_URL')
    api_key = os.environ.get('VANGUARD_API_KEY')

    if not api_url or not api_key:
        print("ERROR: VANGUARD_AGENT_API_URL and VANGUARD_API_KEY environment variables must be set.")
        return

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(api_url, headers=headers, json=cce_payload, timeout=10)
        response.raise_for_status()
        print(f"Successfully sent CCE to Vanguard for target {cce_payload['target_id']}. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to send CCE to Vanguard for target {cce_payload['target_id']}: {e}")

def trigger_remediation(bucket_arn):
    """
    Sends a message to an SQS queue to trigger a downstream remediation playbook.
    """
    sqs_queue_url = os.environ.get('SQS_QUEUE_URL')
    if not sqs_queue_url:
        print("ERROR: SQS_QUEUE_URL environment variable must be set.")
        return

    sqs = boto3.client('sqs')
    message_body = {
        'target_id': bucket_arn,
        'remediation_path': 'https://github.com/wrestcody/Praetorium_Nexus/blob/main/remediation_playbooks/s3_public_access_fix.tf',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }

    try:
        response = sqs.send_message(
            QueueUrl=sqs_queue_url,
            MessageBody=json.dumps(message_body)
        )
        print(f"Successfully sent remediation trigger for {bucket_arn}. Message ID: {response.get('MessageId')}")
    except Exception as e:
        print(f"ERROR: Failed to send remediation trigger for {bucket_arn}: {e}")

def check_public_access_block(s3_client, bucket_name):
    """Checks if a bucket's Public Access Block is fully enabled."""
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
        is_compliant = all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ])
        details = "Public access block is enabled." if is_compliant else "Public access block is not fully enabled."
        return {"check_id": "S3.1_Public_Access_Blocked", "status": "PASS" if is_compliant else "FAIL", "details": details}
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {"check_id": "S3.1_Public_Access_Blocked", "status": "FAIL", "details": "Public access block configuration is missing."}
        raise

def check_default_encryption(s3_client, bucket_name):
    """Checks if a bucket has default server-side encryption enabled."""
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        is_compliant = bool(encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules'))
        details = "Default encryption (AES256 or KMS) is enabled." if is_compliant else "Default encryption is not enabled."
        return {"check_id": "S3.5_Server_Side_Encryption", "status": "PASS" if is_compliant else "FAIL", "details": details}
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return {"check_id": "S3.5_Server_Side_Encryption", "status": "FAIL", "details": "Default encryption configuration is missing."}
        raise

def lambda_handler(event, context):
    """
    Checks S3 buckets for compliance, generates a consolidated CCE payload,
    sends it to Vanguard, and triggers remediation if necessary.
    """
    s3 = boto3.client('s3')
    processed_buckets = 0

    try:
        for bucket in s3.list_buckets().get('Buckets', []):
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"

            # Aggregate findings from all checks for the bucket
            findings = [
                check_public_access_block(s3, bucket_name),
                check_default_encryption(s3, bucket_name)
            ]

            # Determine the overall status for the bucket
            overall_status = "PASS" if all(f['status'] == 'PASS' for f in findings) else "FAIL"

            # Construct the final CCE payload
            cce_payload = {
                "engine_id": "KSI_Engine",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "target_id": bucket_arn,
                "control_id": "NIST-800-53-CM-6",
                "status": overall_status,
                "findings": findings,
                "remediation_path": "https://github.com/wrestcody/Praetorium_Nexus/blob/main/remediation_playbooks/s3_public_access_fix.tf"
            }

            # Send the payload to the downstream agent
            send_cce_to_vanguard(cce_payload)

            # If the overall status is a failure, trigger one remediation action
            if overall_status == "FAIL":
                trigger_remediation(bucket_arn)

            processed_buckets += 1

    except Exception as e:
        print(f"An unexpected error occurred during bucket processing: {e}")
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

    return {
        'statusCode': 200,
        'body': json.dumps({'message': f'Successfully processed {processed_buckets} buckets.'})
    }
