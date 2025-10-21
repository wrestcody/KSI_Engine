import json
import boto3
import datetime

def create_cce_payload(bucket_arn, timestamp, status, finding, pass_fail_criteria, raw_severity='N/A', remediation_playbook_ref='N/A'):
    """Helper function to create a Continuous Compliance Evidence (CCE) payload."""
    return {
        'KSI_ID': 'KSI-SVC-04',
        'Control_ID': 'CM-6',
        'Resource_ID': bucket_arn,
        'Validation_Type': 'Automated',
        'Pass_Fail_Criteria': pass_fail_criteria,
        'Status': status,
        'Raw_Severity': raw_severity,
        'Finding': finding,
        'Remediation_Playbook_Ref': remediation_playbook_ref,
        'Validation_Timestamp': timestamp
    }

def lambda_handler(event, context):
    """
    Checks S3 buckets for compliance with FedRAMP 20x / NIST 800-53 CM-6
    and generates a Persistent Validation Agent (PVA) CCE payload for each check.
    """
    s3 = boto3.client('s3')
    evidence_records = []
    timestamp = datetime.datetime.utcnow().isoformat()

    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"

            # 1. Check Public Access Block configuration
            is_public_access_compliant = False
            finding_public_access = f"S3 Bucket '{bucket_name}' does not enforce public access blocking or a configuration is missing."
            try:
                pub_access_block = s3.get_public_access_block(Bucket=bucket_name)
                config = pub_access_block.get('PublicAccessBlockConfiguration', {})
                if (config.get('BlockPublicAcls', False) and
                    config.get('IgnorePublicAcls', False) and
                    config.get('BlockPublicPolicy', False) and
                    config.get('RestrictPublicBuckets', False)):
                    is_public_access_compliant = True
                    finding_public_access = f"S3 Bucket '{bucket_name}' enforces public access blocking."
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    raise e # Re-raise unexpected errors

            pass_fail_criteria_public = 'All Public Access Block settings MUST be True.'
            if is_public_access_compliant:
                evidence_records.append(create_cce_payload(bucket_arn, timestamp, 'PASS', finding_public_access, pass_fail_criteria_public))
            else:
                evidence_records.append(create_cce_payload(bucket_arn, timestamp, 'FAIL', finding_public_access, pass_fail_criteria_public, 'High', 'remediation_playbooks/s3_public_access_fix.tf'))

            # 2. Check for default encryption
            is_encryption_compliant = False
            finding_encryption = f"S3 Bucket '{bucket_name}' does not have default encryption enabled."
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                if encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules'):
                    is_encryption_compliant = True
                    finding_encryption = f"S3 Bucket '{bucket_name}' has default encryption enabled."
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    raise e # Re-raise unexpected errors

            pass_fail_criteria_encryption = 'Default encryption MUST be enabled.'
            if is_encryption_compliant:
                evidence_records.append(create_cce_payload(bucket_arn, timestamp, 'PASS', finding_encryption, pass_fail_criteria_encryption))
            else:
                evidence_records.append(create_cce_payload(bucket_arn, timestamp, 'FAIL', finding_encryption, pass_fail_criteria_encryption, 'High', 'remediation_playbooks/s3_public_access_fix.tf'))


    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    # Log each record for visibility
    for record in evidence_records:
        print(json.dumps(record, indent=4))

    return {
        'statusCode': 200,
        'body': json.dumps({'evidence_records': evidence_records})
    }
