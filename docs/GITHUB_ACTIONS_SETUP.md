# GitHub Actions Setup Guide

This guide explains how to configure GitHub repository secrets for CI/CD workflows.

## Required Secrets

The deployment workflow requires the following secrets to be configured in your GitHub repository.

### AWS Credentials

1. Go to your repository on GitHub
2. Navigate to Settings > Secrets and variables > Actions
3. Click "New repository secret"
4. Add the following secrets:

AWS_ACCESS_KEY_ID
- Description: AWS access key for deployment
- Value: Your AWS access key ID (e.g., AKIAIOSFODNN7EXAMPLE)

AWS_SECRET_ACCESS_KEY
- Description: AWS secret access key
- Value: Your AWS secret access key

### Terraform State

TERRAFORM_STATE_BUCKET
- Description: S3 bucket name for Terraform state
- Value: Your Terraform state bucket name (e.g., company-terraform-state)

### Lambda Deployment

LAMBDA_BUCKET_NAME
- Description: S3 bucket for Lambda deployment packages
- Value: Your Lambda artifacts bucket name (e.g., company-lambda-artifacts)

### Slack Notifications (Optional)

SLACK_WEBHOOK_URL
- Description: Slack webhook URL for deployment notifications
- Value: Your Slack webhook URL (e.g., https://hooks.slack.com/services/...)

## Creating AWS IAM User for GitHub Actions

Create a dedicated IAM user with minimal permissions:

```bash
# Create IAM user
aws iam create-user --user-name github-actions-s3-detector

# Create access key
aws iam create-access-key --user-name github-actions-s3-detector
```

Attach this policy to the user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TerraformStateAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::YOUR-TERRAFORM-STATE-BUCKET/*"
    },
    {
      "Sid": "TerraformStateLocking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/terraform-state-lock"
    },
    {
      "Sid": "LambdaDeployment",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::YOUR-LAMBDA-BUCKET/*"
    },
    {
      "Sid": "LambdaUpdate",
      "Effect": "Allow",
      "Action": [
        "lambda:UpdateFunctionCode",
        "lambda:GetFunction",
        "lambda:UpdateFunctionConfiguration"
      ],
      "Resource": "arn:aws:lambda:*:*:function:s3-bucket-detector-*"
    },
    {
      "Sid": "TerraformResourceManagement",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "lambda:*",
        "iam:*",
        "cloudwatch:*",
        "events:*",
        "sqs:*",
        "secretsmanager:*",
        "cloudtrail:*"
      ],
      "Resource": "*"
    }
  ]
}
```

Note: Adjust permissions based on your security requirements. The above policy is permissive for initial setup.

## Workflow Triggers

### CI Workflow
Runs automatically on:
- Push to main or develop branches
- Pull requests to main or develop branches

### Deploy Workflow
Runs manually via GitHub Actions UI:
1. Go to Actions tab
2. Select "Deploy" workflow
3. Click "Run workflow"
4. Choose environment (dev/staging/prod)
5. Click "Run workflow"

## Environment Configuration

Create environment-specific configurations:

1. Go to Settings > Environments
2. Create environments: dev, staging, prod
3. Add environment-specific secrets if needed
4. Configure protection rules for prod environment

## Testing the Setup

### Test CI Workflow

```bash
# Make a small change and push
echo "# Test" >> README.md
git add README.md
git commit -m "test: Trigger CI workflow"
git push origin main
```

Check the Actions tab to see the workflow run.

### Test Deploy Workflow

1. Ensure all secrets are configured
2. Go to Actions > Deploy workflow
3. Click "Run workflow"
4. Select "dev" environment
5. Monitor the deployment

## Troubleshooting

### Error: Credentials could not be loaded

Solution: Verify AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY secrets are set correctly.

### Error: Need to provide at least one botToken or webhookUrl

Solution: This is from the Slack notification step. Either:
- Add SLACK_WEBHOOK_URL secret, or
- The workflow will skip Slack notifications if the secret is not set

### Error: Terraform state bucket not found

Solution: Create the Terraform state bucket first:

```bash
aws s3 mb s3://your-terraform-state-bucket
aws s3api put-bucket-versioning \
  --bucket your-terraform-state-bucket \
  --versioning-configuration Status=Enabled
```

### Error: Lambda bucket not found

Solution: Create the Lambda artifacts bucket:

```bash
aws s3 mb s3://your-lambda-bucket
```

## Disabling Workflows

To disable workflows temporarily:

1. Go to Actions tab
2. Select the workflow
3. Click the "..." menu
4. Select "Disable workflow"

## Security Best Practices

1. Use environment-specific secrets
2. Enable branch protection rules
3. Require pull request reviews
4. Use OIDC instead of long-lived credentials (advanced)
5. Rotate AWS access keys regularly
6. Audit workflow runs periodically
7. Use environment protection rules for production

## Manual Deployment Alternative

If you prefer not to use GitHub Actions, deploy manually:

```bash
# Build Lambda package
cd src
./build.sh

# Upload to S3
aws s3 cp lambda.zip s3://your-lambda-bucket/lambda/s3-detector.zip

# Deploy with Terraform
cd ../terraform
terraform init
terraform plan
terraform apply
```

## References

- GitHub Actions Documentation: https://docs.github.com/en/actions
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Terraform Backend Configuration: https://www.terraform.io/docs/language/settings/backends/s3.html
