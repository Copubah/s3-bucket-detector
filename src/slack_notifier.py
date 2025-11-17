"""
Slack Notifier
Sends formatted alerts to Slack using webhooks or Web API
"""

import json
import logging
from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError
import urllib3
from datetime import datetime

logger = logging.getLogger(__name__)

class SlackNotifier:
    """Sends Slack notifications for S3 bucket detections"""
    
    def __init__(self, secret_arn: str):
        self.secret_arn = secret_arn
        self.secrets_client = boto3.client('secretsmanager')
        self.http = urllib3.PoolManager()
        self._webhook_url = None
        
    def send_alert(self, report: Dict[str, Any]) -> None:
        """
        Send Slack alert for public bucket detection
        
        Args:
            report: Detection/remediation report
        """
        webhook_url = self._get_webhook_url()
        
        if not webhook_url:
            raise Exception("Slack webhook URL not configured")
        
        message = self._build_message(report)
        
        try:
            response = self.http.request(
                'POST',
                webhook_url,
                body=json.dumps(message),
                headers={'Content-Type': 'application/json'},
                timeout=10.0
            )
            
            if response.status != 200:
                raise Exception(f"Slack API returned status {response.status}: {response.data}")
            
            logger.info(f"Slack notification sent for bucket {report['bucket_name']}")
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {str(e)}")
            raise
    
    def _get_webhook_url(self) -> str:
        """Retrieve Slack webhook URL from Secrets Manager"""
        if self._webhook_url:
            return self._webhook_url
        
        try:
            response = self.secrets_client.get_secret_value(SecretId=self.secret_arn)
            secret = json.loads(response['SecretString'])
            self._webhook_url = secret.get('webhook_url', '')
            return self._webhook_url
        except ClientError as e:
            logger.error(f"Failed to retrieve Slack webhook from Secrets Manager: {str(e)}")
            raise
    
    def _build_message(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build Slack message using Block Kit
        
        Args:
            report: Detection/remediation report
            
        Returns:
            Slack message payload
        """
        bucket_name = report['bucket_name']
        account_id = report['account_id']
        region = report['region']
        detection = report['detection_result']
        exposure_types = detection.get('exposure_types', [])
        
        # Determine severity
        severity = self._calculate_severity(detection)
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }.get(severity, '⚪')
        
        # Remediation status
        remediation_result = report.get('remediation_result', {})
        was_remediated = remediation_result.get('success', False)
        actions_taken = remediation_result.get('actions_taken', [])
        
        # Build console links
        bucket_url = f"https://s3.console.aws.amazon.com/s3/buckets/{bucket_name}?region={region}"
        cloudtrail_url = f"https://console.aws.amazon.com/cloudtrail/home?region={region}#/events"
        
        # Format timestamp
        event_time = report.get('event_time', '')
        if event_time:
            try:
                dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except:
                formatted_time = event_time
        else:
            formatted_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} Public S3 Bucket Detected",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Bucket:*\n`{bucket_name}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Account:*\n`{account_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Region:*\n`{region}`"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Exposure Type:*\n{', '.join(exposure_types) if exposure_types else 'Unknown'}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Event:*\n`{report.get('event_name', 'Unknown')}`"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Time:* {formatted_time}\n*User:* `{self._format_user_identity(report.get('user_identity', {}))}`\n*Source IP:* `{report.get('source_ip', 'Unknown')}`"
                }
            }
        ]
        
        # Add remediation status
        if was_remediated:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"✅ *Auto-Remediated*\nActions: {', '.join(actions_taken)}"
                }
            })
        else:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "⚠️ *Manual Remediation Required*\nAuto-remediation is disabled or failed."
                }
            })
        
        # Add action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🔍 View Bucket",
                        "emoji": True
                    },
                    "url": bucket_url,
                    "style": "primary"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "📊 CloudTrail",
                        "emoji": True
                    },
                    "url": cloudtrail_url
                }
            ]
        })
        
        # Add context
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Correlation ID: `{report.get('correlation_id', 'N/A')}` | Environment: `{report.get('auto_remediate_enabled', False) and 'Auto-Remediate ON' or 'Alert-Only'}`"
                }
            ]
        })
        
        return {
            "blocks": blocks,
            "text": f"Public S3 bucket detected: {bucket_name}"  # Fallback text
        }
    
    def _calculate_severity(self, detection: Dict[str, Any]) -> str:
        """
        Calculate severity based on exposure type and bucket contents
        
        Args:
            detection: Detection result
            
        Returns:
            Severity level: critical, high, medium, low
        """
        exposure_types = detection.get('exposure_types', [])
        
        # Critical: Multiple exposure vectors
        if len(exposure_types) >= 2:
            return 'critical'
        
        # High: Public ACL or Policy
        if 'public_acl' in exposure_types or 'public_policy' in exposure_types:
            return 'high'
        
        # Medium: Public Access Block disabled
        if 'public_access_block_disabled' in exposure_types:
            return 'medium'
        
        return 'low'
    
    def _format_user_identity(self, user_identity: Dict[str, Any]) -> str:
        """Format user identity for display"""
        identity_type = user_identity.get('type', 'Unknown')
        
        if identity_type == 'IAMUser':
            return user_identity.get('userName', 'Unknown IAM User')
        elif identity_type == 'AssumedRole':
            arn = user_identity.get('arn', '')
            if arn:
                return arn.split('/')[-1]
            return 'Unknown Role'
        elif identity_type == 'Root':
            return 'Root Account'
        else:
            return user_identity.get('principalId', 'Unknown')
