"""
S3 Bucket Detector Lambda Function
Detects publicly accessible S3 buckets and sends Slack notifications
"""

import json
import logging
import os
import time
from typing import Dict, List, Any
import boto3
from botocore.exceptions import ClientError

from detector import S3BucketDetector
from remediator import S3BucketRemediator
from slack_notifier import SlackNotifier

# Configure logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET_NAME')
SLACK_SECRET_ARN = os.environ.get('SLACK_SECRET_ARN')
AUTO_REMEDIATE = os.environ.get('AUTO_REMEDIATE', 'false').lower() == 'true'
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'prod')

# AWS clients
s3_client = boto3.client('s3')
cloudwatch_client = boto3.client('cloudwatch')

# Initialize components
detector = S3BucketDetector()
remediator = S3BucketRemediator()
slack_notifier = SlackNotifier(SLACK_SECRET_ARN)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function
    
    Args:
        event: SQS event containing CloudTrail S3 API calls
        context: Lambda context object
        
    Returns:
        Response with batch item failures for SQS partial batch responses
    """
    logger.info(f"Processing {len(event.get('Records', []))} records")
    
    batch_item_failures = []
    processed_count = 0
    detected_count = 0
    remediated_count = 0
    
    for record in event.get('Records', []):
        message_id = record['messageId']
        
        try:
            # Parse SQS message
            body = json.loads(record['body'])
            
            # Extract CloudTrail event
            if 'detail' in body:
                # EventBridge format
                cloudtrail_event = body
            else:
                # Direct CloudTrail format
                cloudtrail_event = body
            
            # Process the event
            result = process_cloudtrail_event(cloudtrail_event, context)
            
            if result['detected']:
                detected_count += 1
            if result['remediated']:
                remediated_count += 1
                
            processed_count += 1
            
        except Exception as e:
            logger.error(f"Error processing message {message_id}: {str(e)}", exc_info=True)
            batch_item_failures.append({'itemIdentifier': message_id})
    
    # Publish metrics
    publish_metrics(processed_count, detected_count, remediated_count)
    
    logger.info(f"Processed: {processed_count}, Detected: {detected_count}, Remediated: {remediated_count}")
    
    return {
        'statusCode': 200,
        'batchItemFailures': batch_item_failures
    }


def process_cloudtrail_event(event: Dict[str, Any], context: Any) -> Dict[str, bool]:
    """
    Process a single CloudTrail event
    
    Args:
        event: CloudTrail event
        context: Lambda context
        
    Returns:
        Dictionary with detection and remediation status
    """
    result = {
        'detected': False,
        'remediated': False
    }
    
    # Extract event details
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    bucket_name = extract_bucket_name(detail)
    
    if not bucket_name:
        logger.warning(f"Could not extract bucket name from event: {event_name}")
        return result
    
    logger.info(f"Processing {event_name} for bucket: {bucket_name}")
    
    # Detect public access
    detection_result = detector.check_bucket_public_access(bucket_name)
    
    if not detection_result['is_public']:
        logger.info(f"Bucket {bucket_name} is not public")
        return result
    
    result['detected'] = True
    logger.info(f"Public bucket detected: {bucket_name}")
    
    # Generate correlation ID for tracking
    correlation_id = f"{context.request_id}-{int(time.time())}"
    
    # Prepare detection report
    report = {
        'correlation_id': correlation_id,
        'timestamp': time.time(),
        'bucket_name': bucket_name,
        'account_id': detail.get('userIdentity', {}).get('accountId', 'unknown'),
        'region': detail.get('awsRegion', 'unknown'),
        'event_name': event_name,
        'event_time': detail.get('eventTime', ''),
        'user_identity': detail.get('userIdentity', {}),
        'source_ip': detail.get('sourceIPAddress', 'unknown'),
        'detection_result': detection_result,
        'auto_remediate_enabled': AUTO_REMEDIATE
    }
    
    # Attempt remediation if enabled
    if AUTO_REMEDIATE:
        try:
            remediation_result = remediator.remediate_bucket(bucket_name, detection_result)
            report['remediation_result'] = remediation_result
            result['remediated'] = remediation_result['success']
            
            if remediation_result['success']:
                logger.info(f"Remediation performed for bucket: {bucket_name}")
        except Exception as e:
            logger.error(f"Remediation failed for bucket {bucket_name}: {str(e)}")
            report['remediation_error'] = str(e)
    
    # Save audit report to S3
    save_audit_report(report)
    
    # Send Slack notification
    try:
        slack_notifier.send_alert(report)
    except Exception as e:
        logger.error(f"Slack notification failed: {str(e)}")
        # Don't fail the entire process if Slack fails
    
    return result


def extract_bucket_name(detail: Dict[str, Any]) -> str:
    """
    Extract bucket name from CloudTrail event detail
    
    Args:
        detail: CloudTrail event detail
        
    Returns:
        Bucket name or empty string
    """
    # Try requestParameters first
    request_params = detail.get('requestParameters', {})
    
    if 'bucketName' in request_params:
        return request_params['bucketName']
    
    if 'bucket' in request_params:
        return request_params['bucket']
    
    # Try resources
    resources = detail.get('resources', [])
    for resource in resources:
        if resource.get('type') == 'AWS::S3::Bucket':
            arn = resource.get('ARN', '')
            if arn.startswith('arn:aws:s3:::'):
                return arn.split(':::')[1].split('/')[0]
    
    return ''


def save_audit_report(report: Dict[str, Any]) -> None:
    """
    Save audit report to S3
    
    Args:
        report: Detection/remediation report
    """
    try:
        timestamp = time.strftime('%Y/%m/%d', time.gmtime(report['timestamp']))
        key = f"reports/{timestamp}/{report['correlation_id']}.json"
        
        s3_client.put_object(
            Bucket=REPORTS_BUCKET,
            Key=key,
            Body=json.dumps(report, indent=2, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        
        logger.info(f"Audit report saved: s3://{REPORTS_BUCKET}/{key}")
        
    except ClientError as e:
        logger.error(f"Failed to save audit report: {str(e)}")


def publish_metrics(processed: int, detected: int, remediated: int) -> None:
    """
    Publish custom CloudWatch metrics
    
    Args:
        processed: Number of events processed
        detected: Number of public buckets detected
        remediated: Number of buckets remediated
    """
    try:
        cloudwatch_client.put_metric_data(
            Namespace='S3BucketDetector',
            MetricData=[
                {
                    'MetricName': 'EventsProcessed',
                    'Value': processed,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                },
                {
                    'MetricName': 'PublicBucketsDetected',
                    'Value': detected,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                },
                {
                    'MetricName': 'RemediationsPerformed',
                    'Value': remediated,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ]
                }
            ]
        )
    except ClientError as e:
        logger.error(f"Failed to publish metrics: {str(e)}")
