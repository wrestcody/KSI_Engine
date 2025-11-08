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
import logging
from botocore.exceptions import ClientError
from typing import Dict, Any, List, Optional

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass

class AppConfig:
    """Handles loading and validation of environment variables."""
    def __init__(self):
        self.vanguard_agent_api_url = os.environ.get('VANGUARD_AGENT_API_URL')
        self.vanguard_api_key = os.environ.get('VANGUARD_API_KEY')
        self.sqs_queue_url = os.environ.get('SQS_QUEUE_URL')
        self.remediation_path = os.environ.get('REMEDIATION_PATH', 'https://github.com/wrestcody/Praetorium_Nexus/blob/main/remediation_playbooks/s3_public_access_fix.tf')
        self.validate()

    def validate(self):
        """Ensures all required environment variables are set."""
        if not self.vanguard_agent_api_url or not self.vanguard_api_key:
            raise ConfigError("VANGUARD_AGENT_API_URL and VANGUARD_API_KEY must be set.")
        if not self.sqs_queue_url:
            raise ConfigError("SQS_QUEUE_URL must be set.")

# Initialize clients once to be reused across invocations
try:
    CONFIG = AppConfig()
    BOTO3_CLIENTS = {
        's3': boto3.client('s3'),
        'sqs': boto3.client('sqs')
    }
except ConfigError as e:
    logger.critical(f"Configuration Error: {e}")
    # The Lambda will fail to initialize if config is bad
    raise

def send_cce_to_vanguard(cce_payload: Dict[str, Any]):
    """Securely sends the CCE payload to the Vanguard_Agent API endpoint."""
    headers = {
        'Authorization': f'Bearer {CONFIG.vanguard_api_key}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(CONFIG.vanguard_agent_api_url, headers=headers, json=cce_payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Successfully sent CCE to Vanguard for target {cce_payload['target_id']}. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send CCE to Vanguard for target {cce_payload['target_id']}: {e}")

def trigger_remediation(bucket_arn: str):
    """Sends a message to an SQS queue to trigger a downstream remediation playbook."""
    message_body = {
        'target_id': bucket_arn,
        'remediation_path': CONFIG.remediation_path,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    try:
        response = BOTO3_CLIENTS['sqs'].send_message(
            QueueUrl=CONFIG.sqs_queue_url,
            MessageBody=json.dumps(message_body)
        )
        logger.info(f"Successfully sent remediation trigger for {bucket_arn}. Message ID: {response.get('MessageId')}")
    except ClientError as e:
        logger.error(f"Failed to send remediation trigger for {bucket_arn}: {e}")

def check_public_access_block(s3_client: Any, bucket_name: str) -> Dict[str, str]:
    """Checks if a bucket's Public Access Block is fully enabled."""
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
        is_compliant = all(config.get(key, False) for key in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'])
        details = "Public access block is enabled." if is_compliant else "Public access block is not fully enabled."
        return {"check_id": "S3.1_Public_Access_Blocked", "status": "PASS" if is_compliant else "FAIL", "details": details}
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {"check_id": "S3.1_Public_Access_Blocked", "status": "FAIL", "details": "Public access block configuration is missing."}
        logger.error(f"Error checking public access block for {bucket_name}: {e}")
        raise

def check_default_encryption(s3_client: Any, bucket_name: str) -> Dict[str, str]:
    """Checks if a bucket has default server-side encryption enabled."""
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        is_compliant = bool(encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules'))
        details = "Default encryption (AES256 or KMS) is enabled." if is_compliant else "Default encryption is not enabled."
        return {"check_id": "S3.5_Server_Side_Encryption", "status": "PASS" if is_compliant else "FAIL", "details": details}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return {"check_id": "S3.5_Server_Side_Encryption", "status": "FAIL", "details": "Default encryption configuration is missing."}
        logger.error(f"Error checking default encryption for {bucket_name}: {e}")
        raise

def check_bucket_versioning(s3_client: Any, bucket_name: str) -> Dict[str, str]:
    """Checks if a bucket has versioning enabled."""
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        is_compliant = versioning.get('Status') == 'Enabled'
        details = "Bucket versioning is enabled." if is_compliant else "Bucket versioning is not enabled."
        return {"check_id": "S3.6_Bucket_Versioning", "status": "PASS" if is_compliant else "FAIL", "details": details}
    except ClientError as e:
        logger.error(f"Error checking bucket versioning for {bucket_name}: {e}")
        raise

def create_cce_payload(bucket_arn: str, findings: List[Dict[str, str]], overall_status: str) -> Dict[str, Any]:
    """Constructs the final CCE payload."""
    return {
        "engine_id": "KSI_Engine",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "target_id": bucket_arn,
        "control_id": "NIST-800-53-CM-6",
        "status": overall_status,
        "findings": findings,
        "remediation_path": CONFIG.remediation_path
    }

def process_bucket(s3_client: Any, bucket_name: str):
    """Processes a single S3 bucket for compliance."""
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    try:
        findings = [
            check_public_access_block(s3_client, bucket_name),
            check_default_encryption(s3_client, bucket_name),
            check_bucket_versioning(s3_client, bucket_name)
        ]
        overall_status = "PASS" if all(f['status'] == 'PASS' for f in findings) else "FAIL"
        cce_payload = create_cce_payload(bucket_arn, findings, overall_status)
        send_cce_to_vanguard(cce_payload)
        if overall_status == "FAIL":
            trigger_remediation(bucket_arn)
        return True
    except Exception as e:
        logger.error(f"Failed to process bucket {bucket_name}: {e}")
        return False

def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """
    Checks S3 buckets for compliance, generates a consolidated CCE payload,
    sends it to Vanguard, and triggers remediation if necessary.
    """
    s3_client = BOTO3_CLIENTS['s3']
    processed_buckets = 0
    try:
        buckets = s3_client.list_buckets().get('Buckets', [])
        for bucket in buckets:
            if process_bucket(s3_client, bucket['Name']):
                processed_buckets += 1
    except ClientError as e:
        logger.critical(f"An unexpected error occurred during bucket listing: {e}")
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

    logger.info(f'Successfully processed {processed_buckets} buckets.')
    return {
        'statusCode': 200,
        'body': json.dumps({'message': f'Successfully processed {processed_buckets} buckets.'})
    }
