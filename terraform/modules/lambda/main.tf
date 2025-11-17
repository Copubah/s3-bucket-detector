data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# IAM role for Lambda function
resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM policy for Lambda function - Least privilege
resource "aws_iam_role_policy" "lambda" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}*"
        # Why: Lambda needs to write logs to CloudWatch for debugging and audit
      },
      {
        Sid    = "SQSQueueAccess"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = var.sqs_queue_arn
        # Why: Lambda needs to consume messages from SQS queue
      },
      {
        Sid    = "S3BucketInspection"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging"
        ]
        Resource = "arn:aws:s3:::*"
        # Why: Lambda needs to inspect bucket configuration to detect public access
        # Note: Cannot be scoped to specific buckets as we monitor all buckets
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
        # Why: Lambda needs to remediate public buckets by applying security controls
        # Note: Only used when AUTO_REMEDIATE=true
      },
      {
        Sid    = "S3ReportsWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${var.reports_bucket_name}/*"
        # Why: Lambda writes audit reports to the reports bucket
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = var.slack_secret_arn
        # Why: Lambda retrieves Slack webhook URL from Secrets Manager
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "S3BucketDetector"
          }
        }
        # Why: Lambda publishes custom metrics for monitoring
      },
      {
        Sid    = "CloudTrailLookup"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
        # Why: Lambda queries CloudTrail to get additional context about changes
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-logs"
  })
}

# Lambda function
resource "aws_lambda_function" "detector" {
  function_name = var.project_name
  role          = aws_iam_role.lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  s3_bucket = var.lambda_bucket_name
  s3_key    = var.lambda_s3_key

  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = {
      REPORTS_BUCKET_NAME = var.reports_bucket_name
      SLACK_SECRET_ARN    = var.slack_secret_arn
      AUTO_REMEDIATE      = tostring(var.auto_remediate)
      LOG_LEVEL           = var.environment == "prod" ? "INFO" : "DEBUG"
      ENVIRONMENT         = var.environment
    }
  }

  tracing_config {
    mode = "Active"  # Enable X-Ray tracing
  }

  dead_letter_config {
    target_arn = var.sqs_queue_arn
  }

  tags = merge(var.tags, {
    Name = var.project_name
  })

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda
  ]
}

# Lambda function alias for blue/green deployments
resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.detector.function_name
  function_version = "$LATEST"

  lifecycle {
    ignore_changes = [function_version]
  }
}
