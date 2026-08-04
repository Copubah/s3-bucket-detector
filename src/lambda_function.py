"""
S3 Bucket Detector Lambda Function
Detects publicly accessible S3 buckets and sends Slack notifications
"""

import json
import logging
import os
import time
from typing import Dict, Any
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
IDEMPOTENCY_TABLE = os.environ.get('IDEMPOTENCY_TABLE_NAME')

# AWS clients
s3_client = boto3.client('s3')
cloudwatch_client = boto3.client('cloudwatch')
dynamodb_client = boto3.client('dynamodb') if IDEMPOTENCY_TABLE else None

# Initialize components
detector = S3BucketDetector()
remediator = S3BucketRemediator()
slack_notifier = SlackNotifier(SLACK_SECRET_ARN)

# TTL for idempotency records: 24 hours
_IDEMPOTENCY_TTL_SECONDS = 86400


def _is_duplicate_event(event_id: str) -> bool:
    """
    Attempt to claim an event_id in the idempotency table using a conditional
    put_item.  Returns True if the event was already processed (condition
    failed), False if this is the first time we've seen it.

    If IDEMPOTENCY_TABLE is not configured the check is skipped (returns False).
    """
    if not dynamodb_client or not IDEMPOTENCY_TABLE:
        return False

    ttl = int(time.time()) + _IDEMPOTENCY_TTL_SECONDS
    try:
        dynamodb_client.put_item(
            TableName=IDEMPOTENCY_TABLE,
            Item={
                'event_id': {'S': event_id},
                'ttl': {'N': str(ttl)}
            },
            ConditionExpression='attribute_not_exists(event_id)'
        )
        return False  # Successfully inserted — first time seeing this event
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return True  # Already processed
        # Unexpected error — log and allow processing to continue rather than
        # dropping the event silently
        logger.error('Idempotency check failed for event %s: %s', event_id, e)
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function

    Args:
        event: SQS event containing CloudTrail S3 API calls
        context: Lambda context object

    Returns:
        Response with batch item failures for SQS partial batch responses
    """
    logger.info('Processing %d records', len(event.get('Records', [])))

    batch_item_failures = []
    processed_count = 0
    detected_count = 0
    remediated_count = 0

    for record in event.get('Records', []):
        message_id = record['messageId']

        try:
            # Parse SQS message body
            body = json.loads(record['body'])

            # Normalise to a CloudTrail event.
            # EventBridge wraps the CloudTrail detail under a 'detail' key;
            # raw CloudTrail records arrive without that wrapper.
            # In both cases we pass the full body to process_cloudtrail_event,
            # which reads event data from body['detail'].
            cloudtrail_event = body

            # Idempotency: skip events we have already processed (SQS is
            # at-least-once, so redelivery is possible).
            event_id = body.get('detail', {}).get('eventID', '')
            if event_id and _is_duplicate_event(event_id):
                logger.info('Skipping duplicate event %s (message %s)', event_id, message_id)
                processed_count += 1
                continue

            # Process the event
            result = process_cloudtrail_event(cloudtrail_event, context)

            if result['detected']:
                detected_count += 1
            if result['remediated']:
                remediated_count += 1

            processed_count += 1

        except Exception as e:
            logger.error('Error processing message %s: %s', message_id, e, exc_info=True)
            batch_item_failures.append({'itemIdentifier': message_id})

    # Publish metrics
    publish_metrics(processed_count, detected_count, remediated_count)

    logger.info('Processed: %d, Detected: %d, Remediated: %d', processed_count, detected_count, remediated_count)

    return {
        'statusCode': 200,
        'batchItemFailures': batch_item_failures
    }


def process_cloudtrail_event(event: Dict[str, Any], context: Any) -> Dict[str, bool]:
    """
    Process a single CloudTrail event

    Args:
        event: CloudTrail event (EventBridge-wrapped or raw)
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
        logger.warning('Could not extract bucket name from event: %s', event_name)
        return result

    logger.info('Processing %s for bucket: %s', event_name, bucket_name)

    # Detect public access
    detection_result = detector.check_bucket_public_access(bucket_name)

    if not detection_result['is_public']:
        logger.info('Bucket %s is not public', bucket_name)
        return result

    result['detected'] = True
    logger.info('Public bucket detected: %s', bucket_name)

    # Generate correlation ID for tracking
    correlation_id = '%s-%d' % (context.request_id, int(time.time()))

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
                logger.info('Remediation performed for bucket: %s', bucket_name)
        except Exception as e:
            logger.error('Remediation failed for bucket %s: %s', bucket_name, e)
            report['remediation_error'] = str(e)

    # Save audit report to S3
    save_audit_report(report)

    # Send Slack notification
    try:
        slack_notifier.send_alert(report)
    except Exception as e:
        logger.error('Slack notification failed: %s', e)
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
        key = 'reports/%s/%s.json' % (timestamp, report['correlation_id'])

        s3_client.put_object(
            Bucket=REPORTS_BUCKET,
            Key=key,
            Body=json.dumps(report, indent=2, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )

        logger.info('Audit report saved: s3://%s/%s', REPORTS_BUCKET, key)

    except ClientError as e:
        logger.error('Failed to save audit report: %s', e)


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
        logger.error('Failed to publish metrics: %s', e)
