# S3 Bucket Detector - Security Operations Runbook

## Purpose

This runbook provides step-by-step procedures for SOC analysts and security engineers to triage, investigate, and respond to public S3 bucket alerts.

---

## Alert Triage Process

### Step 1: Acknowledge Alert

When you receive a Slack alert in #security-alerts:

1. Click the "Investigate" button to acknowledge
2. Note the following details:
   - Bucket Name: The affected S3 bucket
   - Account ID: AWS account where bucket exists
   - Region: AWS region
   - Exposure Type: ACL, Policy, or Public Access Block
   - Severity: Critical, High, Medium, Low
   - Timestamp: When misconfiguration was detected

### Step 2: Verify the Finding

Check if bucket is truly public:

```bash
# Set variables
BUCKET_NAME="example-bucket"
AWS_PROFILE="production"

# Check bucket ACL
aws s3api get-bucket-acl --bucket $BUCKET_NAME --profile $AWS_PROFILE

# Check bucket policy
aws s3api get-bucket-policy --bucket $BUCKET_NAME --profile $AWS_PROFILE

# Check public access block
aws s3api get-public-access-block --bucket $BUCKET_NAME --profile $AWS_PROFILE

# List bucket contents (first 10 objects)
aws s3 ls s3://$BUCKET_NAME --profile $AWS_PROFILE | head -10
```

Determine exposure scope:
- Is the entire bucket public or just specific objects?
- What type of data is stored? (PII, credentials, internal docs, public assets)
- Who has access? (AllUsers, AuthenticatedUsers, specific principals)

### Step 3: Assess Risk and Impact

Risk Matrix:

| Data Sensitivity | Exposure Type | Severity | Response Time |
|-----------------|---------------|----------|---------------|
| PII/PHI/PCI | Full public read | Critical | Immediate (under 5 min) |
| Internal docs | Full public read | High | under 15 min |
| Credentials/Keys | Any public access | Critical | Immediate (under 5 min) |
| Public assets (CDN) | Intentional public | Low | Review only |
| Test/Dev data | Public read | Medium | under 1 hour |

Questions to answer:
1. Was this change intentional? (Check change management tickets)
2. Who made the change? (Check CloudTrail for user identity)
3. Has data been accessed by unauthorized parties? (Check S3 access logs)
4. Is this a recurring issue for this bucket/team?

### Step 4: Investigate Root Cause

Check CloudTrail for the change event:

```bash
# Find who made the change
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$BUCKET_NAME \
  --max-results 10 \
  --profile $AWS_PROFILE \
  --region us-east-1

# Get detailed event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl \
  --start-time 2025-11-17T00:00:00Z \
  --profile $AWS_PROFILE
```

Common root causes:
- Developer error (copy-paste from tutorial)
- Terraform/CloudFormation misconfiguration
- Compromised IAM credentials
- Automated script with overly permissive settings
- Legacy bucket from before security controls

### Step 5: Containment and Remediation

#### Option A: Automated Remediation Already Applied

If the alert shows "Auto-remediated", verify:

```bash
# Confirm bucket is now private
aws s3api get-public-access-block --bucket $BUCKET_NAME --profile $AWS_PROFILE

# Expected output:
# {
#     "PublicAccessBlockConfiguration": {
#         "BlockPublicAcls": true,
#         "IgnorePublicAcls": true,
#         "BlockPublicPolicy": true,
#         "RestrictPublicBuckets": true
#     }
# }
```

If application is broken after remediation:
1. Contact bucket owner immediately
2. Determine if public access was intentional
3. If legitimate use case, implement proper solution (CloudFront, presigned URLs)

#### Option B: Manual Remediation Required

Immediate containment (Critical/High severity):

```bash
# Block all public access (recommended)
aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile $AWS_PROFILE

# Remove public ACL
aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private --profile $AWS_PROFILE

# Remove public bucket policy (if exists)
aws s3api delete-bucket-policy --bucket $BUCKET_NAME --profile $AWS_PROFILE
```

Verify remediation:

```bash
# Test public access (should fail)
curl -I https://$BUCKET_NAME.s3.amazonaws.com/

# Expected: 403 Forbidden or 404 Not Found
```

### Step 6: Check for Data Exfiltration

Enable S3 access logging (if not already enabled):

```bash
aws s3api put-bucket-logging \
  --bucket $BUCKET_NAME \
  --bucket-logging-status \
    "LoggingEnabled={TargetBucket=security-logs-bucket,TargetPrefix=s3-access-logs/$BUCKET_NAME/}" \
  --profile $AWS_PROFILE
```

Query existing access logs (if available):

```bash
# Download recent access logs
aws s3 sync s3://security-logs-bucket/s3-access-logs/$BUCKET_NAME/ ./logs/ --profile $AWS_PROFILE

# Search for suspicious access patterns
grep -E "REST.GET.OBJECT|REST.HEAD.BUCKET" ./logs/* | \
  grep -v "YOUR_KNOWN_IP_RANGES" | \
  awk '{print $3, $5, $8}' | sort | uniq -c | sort -rn
```

Indicators of compromise:
- High volume of GET requests from unknown IPs
- Requests from Tor exit nodes or known malicious IPs
- Bulk downloads of all objects
- Access from unexpected geographic regions

### Step 7: Notification and Escalation

Notify stakeholders:

```bash
# Find bucket owner
aws s3api get-bucket-tagging --bucket $BUCKET_NAME --profile $AWS_PROFILE | \
  jq -r '.TagSet[] | select(.Key=="Owner") | .Value'

# Send notification
# Use your organization's incident management system (PagerDuty, Opsgenie, etc.)
```

Escalation criteria:
- Immediate escalation (page on-call):
  - PII/PHI/PCI data exposed
  - Evidence of data exfiltration
  - Compromised credentials suspected
  - Regulatory compliance impact (GDPR, HIPAA)

- Standard escalation (email/Slack):
  - Internal documents exposed
  - No evidence of access
  - Remediation successful

### Step 8: Post-Incident Actions

Document the incident:

```bash
# Create incident report
cat > incident_report_$(date +%Y%m%d_%H%M%S).md << EOF
# S3 Public Bucket Incident Report

Incident ID: INC-$(date +%Y%m%d-%H%M%S)
Date: $(date)
Severity: [Critical/High/Medium/Low]

## Summary
- Bucket: $BUCKET_NAME
- Account: [Account ID]
- Region: [Region]
- Exposure Duration: [X minutes/hours]
- Data Exposed: [Description]

## Timeline
- [HH:MM] Misconfiguration occurred
- [HH:MM] Alert triggered
- [HH:MM] Investigation started
- [HH:MM] Remediation completed
- [HH:MM] Incident closed

## Root Cause
[Description of why bucket became public]

## Impact
- Data accessed: [Yes/No/Unknown]
- Compliance impact: [Yes/No]
- Business impact: [Description]

## Remediation
[Actions taken to fix]

## Prevention
[Actions to prevent recurrence]

## Lessons Learned
[Key takeaways]
EOF
```

Preventive measures:

1. Add SCPs (Service Control Policies) to prevent public buckets:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:BlockPublicAcls": "true",
          "s3:BlockPublicPolicy": "true",
          "s3:IgnorePublicAcls": "true",
          "s3:RestrictPublicBuckets": "true"
        }
      }
    }
  ]
}
```

2. Update IAM policies to restrict who can modify bucket policies
3. Add AWS Config rule for continuous compliance checking
4. Conduct training for team that caused the misconfiguration
5. Update IaC templates to include public access block by default

### Step 9: Close Incident

Checklist before closing:
- Bucket is confirmed private
- No evidence of data exfiltration
- Stakeholders notified
- Incident report completed
- Preventive measures implemented or scheduled
- Lessons learned documented

Update Slack thread:
```
Incident resolved
- Remediation: [Description]
- Impact: [None/Limited/Significant]
- Follow-up: [Ticket ID or "None required"]
```

---

## Common Scenarios

### Scenario 1: False Positive - Intentional Public Bucket

Example: CDN origin bucket, public website hosting

Response:
1. Verify with bucket owner that public access is intentional
2. Check if CloudFront or proper access controls are in place
3. Add bucket to allowlist:
```bash
# Tag bucket to exclude from future alerts
aws s3api put-bucket-tagging \
  --bucket $BUCKET_NAME \
  --tagging 'TagSet=[{Key=PublicAccessApproved,Value=true},{Key=ApprovedBy,Value=security-team},{Key=ApprovedDate,Value=2025-11-17}]' \
  --profile $AWS_PROFILE
```
4. Update detector Lambda to skip tagged buckets

### Scenario 2: Compromised Credentials

Indicators:
- Change made by unfamiliar IAM user/role
- Change made outside business hours
- Multiple buckets affected simultaneously
- API calls from unusual geographic location

Response:
1. Immediately disable credentials:
```bash
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name compromised-user
```
2. Remediate all affected buckets
3. Review CloudTrail for all actions by compromised credentials
4. Rotate all credentials for affected account
5. Enable MFA for all IAM users
6. Escalate to security incident response team

### Scenario 3: Terraform/IaC Misconfiguration

Indicators:
- Change made by CI/CD service role
- Multiple resources affected
- Recent deployment or infrastructure change

Response:
1. Remediate bucket immediately
2. Identify the IaC code that caused the issue
3. Fix the code (add public access block)
4. Re-deploy with corrected configuration
5. Add pre-deployment validation to CI/CD pipeline

---

## Slack Workflow Actions

The Slack alert includes interactive buttons:

### 🔍 Investigate
- Marks alert as "Under Investigation"
- Assigns to user who clicked
- Creates incident tracking thread

### ✅ Remediate Now
- Triggers manual remediation Lambda
- Applies public access block
- Posts confirmation in thread

### ⏸️ Suppress
- Adds bucket to temporary suppression list (24 hours)
- Requires justification comment
- Notifies security lead

### 🚨 Escalate
- Pages on-call security engineer
- Creates high-priority incident ticket
- Sends email to security leadership

---

## Metrics and KPIs

Track these metrics for continuous improvement:

- Mean Time to Detect (MTTD): Target under 5 seconds
- Mean Time to Acknowledge (MTTA): Target under 5 minutes
- Mean Time to Remediate (MTTR): Target under 15 minutes
- False Positive Rate: Target under 5%
- Auto-Remediation Success Rate: Target over 95%

---

## Contact Information

- Security Team Slack: #security-team
- On-Call: PagerDuty rotation "Security-OnCall"
- Security Lead: security-lead@company.com
- Compliance Team: compliance@company.com

---

## References

- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [Company Security Incident Response Plan](https://wiki.company.com/security/irp)
