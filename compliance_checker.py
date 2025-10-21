import json
import boto3
import datetime

def lambda_handler(event, context):
    """
    Checks S3 buckets for compliance with FedRAMP/NIST 800-53 CM-6.
    Specifically, it verifies that:
    1. Public access is blocked.
    2. Default encryption is enabled.
    """
    s3 = boto3.client('s3')
    findings = []

    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            timestamp = datetime.datetime.utcnow().isoformat()

            # Check Public Access Block configuration
            try:
                pub_access_block = s3.get_public_access_block(Bucket=bucket_name)
                config = pub_access_block.get('PublicAccessBlockConfiguration', {})
                if not (config.get('BlockPublicAcls', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('RestrictPublicBuckets', False)):
                    findings.append({
                        'NIST_800_53_Control_ID': 'CM-6',
                        'Risk_Severity': 'High',
                        'Resource_ID': bucket_arn,
                        'Finding': f"S3 Bucket '{bucket_name}' does not enforce public access blocking.",
                        'Auditability_Timestamp': timestamp
                    })
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append({
                        'NIST_800_53_Control_ID': 'CM-6',
                        'Risk_Severity': 'High',
                        'Resource_ID': bucket_arn,
                        'Finding': f"S3 Bucket '{bucket_name}' does not have a Public Access Block configuration.",
                        'Auditability_Timestamp': timestamp
                    })

            # Check for default encryption
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if not rules:
                     findings.append({
                        'NIST_800_53_Control_ID': 'CM-6',
                        'Risk_Severity': 'High',
                        'Resource_ID': bucket_arn,
                        'Finding': f"S3 Bucket '{bucket_name}' does not have default encryption enabled.",
                        'Auditability_Timestamp': timestamp
                    })
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        'NIST_800_53_Control_ID': 'CM-6',
                        'Risk_Severity': 'High',
                        'Resource_ID': bucket_arn,
                        'Finding': f"S3 Bucket '{bucket_name}' does not have default encryption enabled.",
                        'Auditability_Timestamp': timestamp
                    })


    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    if findings:
        for finding in findings:
            print(json.dumps(finding, indent=4))

    return {
        'statusCode': 200,
        'body': json.dumps({'findings': findings})
    }
