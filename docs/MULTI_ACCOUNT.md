# Multi-Account Deployment Guide

This guide explains how to deploy the S3 Bucket Detector across multiple AWS accounts using AWS Organizations and centralized monitoring.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Account (Central)                    │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  EventBridge │───▶│  SQS Queue   │───▶│   Lambda     │      │
│  │   Event Bus  │    │              │    │  (Detector)  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         ▲                                         │              │
│         │                                         ▼              │
│         │                                  ┌──────────────┐      │
│         │                                  │    Slack     │      │
│         │                                  └──────────────┘      │
└─────────┼─────────────────────────────────────────────────────────┘
          │
          │ Cross-Account Events
          │
    ┌─────┴─────┬─────────────┬─────────────┐
    │           │             │             │
┌───▼────┐  ┌───▼────┐    ┌───▼────┐    ┌───▼────┐
│ Prod   │  │ Dev    │    │ Test   │    │ Shared │
│ Account│  │ Account│    │ Account│    │ Account│
│        │  │        │    │        │    │        │
│ S3     │  │ S3     │    │ S3     │    │ S3     │
│ Buckets│  │ Buckets│    │ Buckets│    │ Buckets│
└────────┘  └────────┘    └────────┘    └────────┘
```

---

## Deployment Strategy

### Option 1: Centralized Monitoring (Recommended)

Deploy detector in a central security account and collect events from all accounts.

Pros:
- Single pane of glass
- Centralized logging and metrics
- Easier to manage and update
- Lower cost (one Lambda function)

Cons:
- Requires cross-account IAM roles
- Single point of failure
- Higher latency for cross-region events

### Option 2: Distributed Monitoring

Deploy detector in each account independently.

Pros:
- No cross-account dependencies
- Lower latency
- Account isolation

Cons:
- Higher operational overhead
- Duplicate infrastructure costs
- Harder to aggregate metrics

---

## Centralized Deployment Steps

### Step 1: Set Up Security Account

Deploy the main infrastructure in your security/audit account:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars
cat > terraform.tfvars << 'EOF'
aws_region  = "us-east-1"
environment = "prod"
project_name = "s3-bucket-detector"

# Use unique bucket names
reports_bucket_name = "security-s3-detector-reports"
lambda_bucket_name  = "security-s3-detector-lambda"

owner_email = "security-team@company.com"
alert_email = "security-alerts@company.com"

# Enable multi-account monitoring
monitor_all_regions = true
EOF

# Deploy
terraform init
terraform apply
```

### Step 2: Create Cross-Account IAM Role

In each monitored account, create an IAM role that allows the security account to inspect S3 buckets:

```hcl
# File: member-account-role.tf
# Deploy this in each member account

data "aws_caller_identity" "current" {}

locals {
  security_account_id = "123456789012"  # Your security account ID
}

resource "aws_iam_role" "s3_detector_cross_account" {
  name = "S3DetectorCrossAccountRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.security_account_id}:role/s3-bucket-detector-lambda-role"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "s3-detector-${data.aws_caller_identity.current.account_id}"
          }
        }
      }
    ]
  })

  tags = {
    Purpose = "S3 Bucket Detector Cross-Account Access"
  }
}

resource "aws_iam_role_policy" "s3_detector_cross_account" {
  name = "S3DetectorCrossAccountPolicy"
  role = aws_iam_role.s3_detector_cross_account.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3BucketInspection"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid    = "S3BucketRemediation"
        Effect = "Allow"
        Action = [
          "s3:PutBucketAcl",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy"
        ]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}

output "cross_account_role_arn" {
  value = aws_iam_role.s3_detector_cross_account.arn
}
```

Deploy in each member account:

```bash
# In each member account
terraform init
terraform apply

# Note the role ARN output
```

### Step 3: Update Security Account Lambda

Update the Lambda function to assume cross-account roles:

```python
# Add to detector.py

import os
import boto3

class S3BucketDetector:
    def __init__(self):
        self.sts_client = boto3.client('sts')
        self.s3_clients = {}  # Cache clients per account
    
    def _get_s3_client(self, account_id: str):
        """Get S3 client for specific account"""
        if account_id in self.s3_clients:
            return self.s3_clients[account_id]
        
        # Get current account
        current_account = boto3.client('sts').get_caller_identity()['Account']
        
        if account_id == current_account:
            # Same account, use default client
            client = boto3.client('s3')
        else:
            # Cross-account, assume role
            role_arn = f"arn:aws:iam::{account_id}:role/S3DetectorCrossAccountRole"
            external_id = f"s3-detector-{account_id}"
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='S3BucketDetector',
                ExternalId=external_id,
                DurationSeconds=900
            )
            
            credentials = response['Credentials']
            client = boto3.client(
                's3',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        
        self.s3_clients[account_id] = client
        return client
    
    def check_bucket_public_access(self, bucket_name: str, account_id: str = None):
        """Check bucket with cross-account support"""
        if not account_id:
            # Extract from event or use current account
            account_id = boto3.client('sts').get_caller_identity()['Account']
        
        s3_client = self._get_s3_client(account_id)
        
        # Rest of detection logic using s3_client...
```

### Step 4: Set Up EventBridge Cross-Account Rules

In each member account, create EventBridge rule to forward events to security account:

```hcl
# File: member-account-eventbridge.tf

locals {
  security_account_id = "123456789012"
  security_event_bus_arn = "arn:aws:events:us-east-1:${local.security_account_id}:event-bus/s3-detector-bus"
}

resource "aws_cloudwatch_event_rule" "s3_config_changes" {
  name        = "s3-detector-forward-events"
  description = "Forward S3 configuration changes to security account"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "security_account" {
  rule      = aws_cloudwatch_event_rule.s3_config_changes.name
  target_id = "SendToSecurityAccount"
  arn       = local.security_event_bus_arn
  role_arn  = aws_iam_role.eventbridge_cross_account.arn
}

resource "aws_iam_role" "eventbridge_cross_account" {
  name = "EventBridgeCrossAccountRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_cross_account" {
  name = "EventBridgeCrossAccountPolicy"
  role = aws_iam_role.eventbridge_cross_account.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = local.security_event_bus_arn
      }
    ]
  })
}
```

### Step 5: Create Custom Event Bus in Security Account

```hcl
# Add to terraform/main.tf in security account

resource "aws_cloudwatch_event_bus" "s3_detector" {
  name = "s3-detector-bus"

  tags = local.common_tags
}

resource "aws_cloudwatch_event_bus_policy" "allow_member_accounts" {
  event_bus_name = aws_cloudwatch_event_bus.s3_detector.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowMemberAccountsToPutEvents"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::111111111111:root",  # Prod account
            "arn:aws:iam::222222222222:root",  # Dev account
            "arn:aws:iam::333333333333:root"   # Test account
          ]
        }
        Action   = "events:PutEvents"
        Resource = aws_cloudwatch_event_bus.s3_detector.arn
      }
    ]
  })
}

# Update EventBridge rule to use custom bus
resource "aws_cloudwatch_event_rule" "s3_config_changes" {
  name           = "${var.project_name}-s3-config-changes"
  description    = "Capture S3 bucket configuration changes"
  event_bus_name = aws_cloudwatch_event_bus.s3_detector.name

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock"
      ]
    }
  })
}
```

---

## AWS Organizations Integration

### Step 1: Enable CloudTrail Organization Trail

Create an organization-wide CloudTrail in the management account:

```bash
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name organization-cloudtrail-logs \
  --is-organization-trail \
  --is-multi-region-trail

aws cloudtrail start-logging --name organization-trail
```

### Step 2: Deploy Using StackSets

Use CloudFormation StackSets to deploy member account resources:

```bash
# Create StackSet
aws cloudformation create-stack-set \
  --stack-set-name s3-detector-member-account \
  --template-body file://member-account-template.yaml \
  --parameters \
    ParameterKey=SecurityAccountId,ParameterValue=123456789012 \
  --capabilities CAPABILITY_IAM

# Deploy to all accounts in organization
aws cloudformation create-stack-instances \
  --stack-set-name s3-detector-member-account \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-east-1
```

---

## Testing Multi-Account Setup

### Test Cross-Account Access

```bash
# From security account, test assuming role in member account
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/S3DetectorCrossAccountRole \
  --role-session-name test \
  --external-id s3-detector-111111111111

# Use temporary credentials to list buckets
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws s3 ls
```

### Test Event Forwarding

```bash
# In member account, create test bucket with public ACL
aws s3api create-bucket --bucket test-public-$(date +%s) --region us-east-1
aws s3api put-bucket-acl --bucket test-public-* --acl public-read

# Check security account for alert (should arrive within 10 seconds)
aws logs tail /aws/lambda/s3-bucket-detector --follow --region us-east-1
```

---

## Monitoring and Metrics

### CloudWatch Dashboard for Multi-Account

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["S3BucketDetector", "PublicBucketsDetected", {"stat": "Sum", "label": "Total"}],
          ["...", {"stat": "Sum", "label": "Prod", "dimensions": {"Account": "111111111111"}}],
          ["...", {"stat": "Sum", "label": "Dev", "dimensions": {"Account": "222222222222"}}],
          ["...", {"stat": "Sum", "label": "Test", "dimensions": {"Account": "333333333333"}}]
        ],
        "title": "Public Buckets by Account",
        "period": 300
      }
    }
  ]
}
```

---

## Cost Optimization

### Multi-Account Cost Breakdown

| Component | Single Account | 10 Accounts (Centralized) | 10 Accounts (Distributed) |
|-----------|----------------|---------------------------|---------------------------|
| Lambda | $0.60 | $0.80 | $6.00 |
| EventBridge | $0.03 | $0.30 | $0.30 |
| SQS | $0.01 | $0.10 | $0.10 |
| CloudTrail | $0.00 | $0.00 | $0.00 |
| Total/month | $0.64 | $1.20 | $6.40 |

Recommendation: Use centralized monitoring for cost efficiency.

---

## Security Considerations

1. Least Privilege: Cross-account roles should only have necessary S3 permissions
2. External ID: Always use external ID for cross-account role assumption
3. Audit Logging: Enable CloudTrail in all accounts
4. SCPs: Use Service Control Policies to prevent disabling CloudTrail
5. Encryption: Use KMS for cross-account event encryption

---

## Troubleshooting

### Events not arriving from member accounts

1. Check EventBridge rule in member account
2. Verify event bus policy in security account
3. Check IAM role for EventBridge in member account
4. Test with `aws events put-events` manually

### Cross-account role assumption failing

1. Verify role trust policy
2. Check external ID matches
3. Ensure Lambda has `sts:AssumeRole` permission
4. Check role ARN format

### High latency for cross-region events

1. Deploy regional Lambda functions
2. Use EventBridge global endpoints
3. Consider distributed deployment for latency-sensitive workloads

---

## References

- [AWS Organizations Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices.html)
- [EventBridge Cross-Account Events](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cross-account.html)
- [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
