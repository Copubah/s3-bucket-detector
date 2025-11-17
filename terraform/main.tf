terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configure backend in terraform init:
    # terraform init -backend-config="bucket=your-terraform-state-bucket"
    key            = "s3-bucket-detector/terraform.tfstate"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "S3BucketDetector"
      ManagedBy   = "Terraform"
      Environment = var.environment
      CostCenter  = var.cost_center
      Owner       = var.owner_email
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  
  common_tags = {
    Project     = "S3BucketDetector"
    Environment = var.environment
  }
}

# CloudTrail for S3 data events
module "cloudtrail" {
  source = "./modules/cloudtrail"
  
  trail_name              = "${var.project_name}-trail"
  s3_bucket_name          = module.s3_buckets.cloudtrail_bucket_id
  enable_s3_data_events   = var.enable_cloudtrail_s3_data_events
  enable_log_validation   = true
  kms_key_id              = aws_kms_key.cloudtrail.arn
  
  tags = local.common_tags
}

# KMS key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-cloudtrail-key"
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# S3 buckets for reports and Lambda code
module "s3_buckets" {
  source = "./modules/s3"
  
  project_name        = var.project_name
  environment         = var.environment
  reports_bucket_name = var.reports_bucket_name
  lambda_bucket_name  = var.lambda_bucket_name
  
  tags = local.common_tags
}

# EventBridge rule for S3 configuration changes
module "eventbridge" {
  source = "./modules/eventbridge"
  
  project_name       = var.project_name
  sqs_queue_arn      = aws_sqs_queue.detector_queue.arn
  enable_all_regions = var.monitor_all_regions
  
  tags = local.common_tags
}

# SQS queue for buffering events
resource "aws_sqs_queue" "detector_queue_dlq" {
  name                      = "${var.project_name}-dlq"
  message_retention_seconds = 1209600 # 14 days
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-dlq"
  })
}

resource "aws_sqs_queue" "detector_queue" {
  name                       = "${var.project_name}-queue"
  visibility_timeout_seconds = 300 # 5 minutes (6x Lambda timeout)
  message_retention_seconds  = 345600 # 4 days
  receive_wait_time_seconds  = 20 # Long polling
  
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.detector_queue_dlq.arn
    maxReceiveCount     = 3
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-queue"
  })
}

resource "aws_sqs_queue_policy" "detector_queue" {
  queue_url = aws_sqs_queue.detector_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeToSendMessage"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.detector_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = module.eventbridge.eventbridge_rule_arn
          }
        }
      }
    ]
  })
}

# Secrets Manager for Slack webhook
resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "${var.project_name}-slack-webhook"
  description             = "Slack webhook URL for S3 bucket detector alerts"
  recovery_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-slack-webhook"
  })
}

# Note: Secret value must be set manually or via separate process
# aws secretsmanager put-secret-value --secret-id <secret-name> --secret-string '{"webhook_url":"https://hooks.slack.com/..."}'

# Lambda function
module "lambda" {
  source = "./modules/lambda"
  
  project_name           = var.project_name
  environment            = var.environment
  lambda_bucket_name     = module.s3_buckets.lambda_bucket_id
  lambda_s3_key          = var.lambda_s3_key
  reports_bucket_name    = module.s3_buckets.reports_bucket_id
  sqs_queue_arn          = aws_sqs_queue.detector_queue.arn
  slack_secret_arn       = aws_secretsmanager_secret.slack_webhook.arn
  auto_remediate         = var.auto_remediate_enabled
  log_retention_days     = var.log_retention_days
  lambda_timeout         = var.lambda_timeout
  lambda_memory          = var.lambda_memory
  reserved_concurrency   = var.lambda_reserved_concurrency
  
  tags = local.common_tags
}

# CloudWatch monitoring and alarms
module "monitoring" {
  source = "./modules/monitoring"
  
  project_name          = var.project_name
  lambda_function_name  = module.lambda.function_name
  sqs_queue_name        = aws_sqs_queue.detector_queue.name
  dlq_name              = aws_sqs_queue.detector_queue_dlq.name
  sns_alert_email       = var.alert_email
  error_rate_threshold  = var.error_rate_threshold
  dlq_depth_threshold   = var.dlq_depth_threshold
  
  tags = local.common_tags
}

# Lambda event source mapping for SQS
resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.detector_queue.arn
  function_name    = module.lambda.function_arn
  batch_size       = 10
  
  scaling_config {
    maximum_concurrency = var.lambda_reserved_concurrency
  }
  
  function_response_types = ["ReportBatchItemFailures"]
}
