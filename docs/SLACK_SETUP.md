# Slack Integration Setup Guide

This guide walks you through setting up Slack notifications for the S3 Bucket Detector.

---

## Option 1: Incoming Webhook (Recommended)

Incoming Webhooks are the simplest way to post messages to Slack.

### Step 1: Create a Slack App

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click "Create New App"
3. Choose "From scratch"
4. Enter app name: "S3 Bucket Detector"
5. Select your workspace
6. Click "Create App"

### Step 2: Enable Incoming Webhooks

1. In your app settings, click "Incoming Webhooks" in the left sidebar
2. Toggle "Activate Incoming Webhooks" to On
3. Click "Add New Webhook to Workspace"
4. Select the channel where you want alerts (e.g., `#security-alerts`)
5. Click "Allow"

### Step 3: Copy Webhook URL

You'll see a webhook URL like:
```
https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
```

Keep this URL secret. It allows anyone to post to your Slack channel.

### Step 4: Store in AWS Secrets Manager

```bash
# Create the secret
aws secretsmanager create-secret \
  --name s3-detector-slack-webhook \
  --description "Slack webhook for S3 bucket detector" \
  --secret-string '{"webhook_url":"https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}' \
  --region us-east-1

# Verify it was created
aws secretsmanager describe-secret \
  --secret-id s3-detector-slack-webhook \
  --region us-east-1
```

### Step 5: Test the Webhook

```bash
# Test with curl
curl -X POST \
  -H 'Content-type: application/json' \
  --data '{"text":"🧪 Test message from S3 Bucket Detector"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

You should see a message appear in your Slack channel!

---

## Option 2: Slack Bot with OAuth (Advanced)

For more advanced features like interactive buttons and user mentions, use a Slack Bot.

### Step 1: Create a Slack App

Follow the same steps as Option 1, Step 1.

### Step 2: Configure Bot Permissions

1. In your app settings, click "OAuth & Permissions"
2. Scroll to "Scopes" → "Bot Token Scopes"
3. Add the following scopes:
   - `chat:write` - Post messages
   - `chat:write.public` - Post to public channels without joining
   - `files:write` - Upload files (optional)

### Step 3: Install App to Workspace

1. Scroll to top of "OAuth & Permissions" page
2. Click "Install to Workspace"
3. Review permissions and click "Allow"
4. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

### Step 4: Store Token in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name s3-detector-slack-token \
  --description "Slack bot token for S3 bucket detector" \
  --secret-string '{"bot_token":"xoxb-YOUR-TOKEN-HERE","channel":"#security-alerts"}' \
  --region us-east-1
```

### Step 5: Update Lambda Code

Modify `slack_notifier.py` to use the Web API:

```python
import json
import boto3
import urllib3

class SlackNotifier:
    def __init__(self, secret_arn: str):
        self.secret_arn = secret_arn
        self.secrets_client = boto3.client('secretsmanager')
        self.http = urllib3.PoolManager()
        self._bot_token = None
        self._channel = None
    
    def _get_credentials(self):
        if self._bot_token:
            return self._bot_token, self._channel
        
        response = self.secrets_client.get_secret_value(SecretId=self.secret_arn)
        secret = json.loads(response['SecretString'])
        self._bot_token = secret.get('bot_token')
        self._channel = secret.get('channel')
        return self._bot_token, self._channel
    
    def send_alert(self, report: dict):
        bot_token, channel = self._get_credentials()
        message = self._build_message(report)
        
        response = self.http.request(
            'POST',
            'https://slack.com/api/chat.postMessage',
            body=json.dumps({
                'channel': channel,
                'blocks': message['blocks'],
                'text': message['text']
            }),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {bot_token}'
            }
        )
        
        result = json.loads(response.data.decode('utf-8'))
        if not result.get('ok'):
            raise Exception(f"Slack API error: {result.get('error')}")
```

---

## Slack Message Format

### Example Alert Message

The detector sends rich, formatted messages using Slack Block Kit:

```
[CRITICAL] Public S3 Bucket Detected

Bucket: test-public-bucket
Severity: HIGH
Account: 123456789012
Region: us-east-1

Exposure Type: public_acl
Event: PutBucketAcl

Time: 2025-11-17 10:30:45 UTC
User: john.doe
Source IP: 192.0.2.1

Manual Remediation Required
Auto-remediation is disabled or failed.

[🔍 View Bucket] [📊 CloudTrail]

Correlation ID: abc-123-def | Environment: Alert-Only
```

### Message Components

1. Header: Severity emoji + title
2. Bucket Info: Name, account, region
3. Detection Details: Exposure type, triggering event
4. Context: Timestamp, user, source IP
5. Remediation Status: Auto-remediated or manual action needed
6. Action Buttons: Links to AWS Console
7. Footer: Correlation ID, environment

---

## Interactive Buttons (Optional)

To add interactive buttons that trigger Lambda functions:

### Step 1: Enable Interactivity

1. In your Slack app settings, click "Interactivity & Shortcuts"
2. Toggle "Interactivity" to On
3. Enter Request URL: Your API Gateway endpoint (see below)
4. Click "Save Changes"

### Step 2: Create API Gateway

```bash
# Create API Gateway to handle Slack interactions
aws apigateway create-rest-api \
  --name s3-detector-slack-actions \
  --description "Handle Slack interactive actions"
```

### Step 3: Add Interactive Buttons to Message

Update `_build_message()` in `slack_notifier.py`:

```python
blocks.append({
    "type": "actions",
    "block_id": "remediation_actions",
    "elements": [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "✅ Remediate Now"},
            "style": "primary",
            "value": f"remediate_{bucket_name}",
            "action_id": "remediate_bucket"
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "⏸️ Suppress"},
            "value": f"suppress_{bucket_name}",
            "action_id": "suppress_alert"
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "🚨 Escalate"},
            "style": "danger",
            "value": f"escalate_{bucket_name}",
            "action_id": "escalate_incident"
        }
    ]
})
```

---

## Testing

### Test Webhook Locally

```bash
# Create test payload
cat > test_slack_payload.json << 'EOF'
{
  "correlation_id": "test-123",
  "timestamp": 1700000000,
  "bucket_name": "test-bucket",
  "account_id": "123456789012",
  "region": "us-east-1",
  "event_name": "PutBucketAcl",
  "event_time": "2025-11-17T10:00:00Z",
  "user_identity": {"type": "IAMUser", "userName": "test-user"},
  "source_ip": "192.0.2.1",
  "detection_result": {
    "is_public": true,
    "exposure_types": ["public_acl"]
  },
  "auto_remediate_enabled": false
}
EOF

# Test with Python
python3 << 'EOF'
import json
from slack_notifier import SlackNotifier

with open('test_slack_payload.json') as f:
    report = json.load(f)

notifier = SlackNotifier('arn:aws:secretsmanager:us-east-1:123456789012:secret:s3-detector-slack-webhook')
notifier.send_alert(report)
print("✅ Test message sent!")
EOF
```

### Test from Lambda

```bash
# Invoke Lambda with test event
aws lambda invoke \
  --function-name s3-bucket-detector \
  --payload file://test_event.json \
  --log-type Tail \
  response.json

# Check logs
aws logs tail /aws/lambda/s3-bucket-detector --follow
```

---

## Troubleshooting

### No messages appearing in Slack

1. Check webhook URL:
   ```bash
   aws secretsmanager get-secret-value \
     --secret-id s3-detector-slack-webhook \
     --query SecretString \
     --output text | jq .
   ```

2. Test webhook manually:
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Test"}' \
     YOUR_WEBHOOK_URL
   ```

3. Check Lambda logs:
   ```bash
   aws logs tail /aws/lambda/s3-bucket-detector --follow
   ```

4. Verify IAM permissions:
   - Lambda needs `secretsmanager:GetSecretValue` permission
   - Check Lambda execution role

### Messages are malformed

1. Validate JSON:
   ```bash
   # Test message building
   python3 -c "
   from slack_notifier import SlackNotifier
   import json
   notifier = SlackNotifier('test')
   msg = notifier._build_message({...})
   print(json.dumps(msg, indent=2))
   "
   ```

2. Use Slack Block Kit Builder:
   - [https://app.slack.com/block-kit-builder](https://app.slack.com/block-kit-builder)
   - Paste your message JSON to validate

### Rate limiting

Slack has rate limits:
- Incoming Webhooks: 1 message per second
- Web API: Varies by method (typically 1-20 req/sec)

If you hit rate limits:
1. Implement exponential backoff
2. Batch multiple detections into one message
3. Use SQS to buffer notifications

---

## Security Best Practices

Do:
- Store webhook URL in Secrets Manager
- Use IAM policies to restrict access to secret
- Rotate webhook URL periodically
- Use HTTPS for all Slack API calls
- Enable CloudTrail logging for Secrets Manager access

Do not:
- Hardcode webhook URL in code
- Store webhook URL in environment variables
- Commit webhook URL to Git
- Share webhook URL in documentation
- Use webhook URL in multiple applications

---

## Advanced: Slack App Distribution

To distribute your Slack app to multiple workspaces:

1. In app settings, go to "Manage Distribution"
2. Complete the checklist:
   - Add app icon
   - Add description
   - Set up OAuth redirect URLs
3. Click "Activate Public Distribution"
4. Share the installation link

---

## Support

- Slack API Documentation: [https://api.slack.com/](https://api.slack.com/)
- Block Kit Builder: [https://app.slack.com/block-kit-builder](https://app.slack.com/block-kit-builder)
- Slack Community: [https://slackcommunity.com/](https://slackcommunity.com/)
