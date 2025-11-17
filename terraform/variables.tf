variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "s3-bucket-detector"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "owner_email" {
  description = "Email of the project owner"
  type        = string
}

variable "cost_center" {
  description = "Cost center for billing"
  type        = string
  default     = "Security"
}

variable "reports_bucket_name" {
  description = "S3 bucket name for storing detection reports"
  type        = string
}

variable "lambda_bucket_name" {
  description = "S3 bucket name for Lambda deployment packages"
  type        = string
}

variable "lambda_s3_key" {
  description = "S3 key for Lambda deployment package"
  type        = string
  default     = "lambda/s3-detector.zip"
}

variable "auto_remediate_enabled" {
  description = "Enable automatic remediation of public buckets"
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention value."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
  
  validation {
    condition     = var.lambda_timeout >= 3 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 3 and 900 seconds."
  }
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 512
  
  validation {
    condition     = var.lambda_memory >= 128 && var.lambda_memory <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrent executions for Lambda function"
  type        = number
  default     = 10
}

variable "error_rate_threshold" {
  description = "Error rate threshold percentage for CloudWatch alarms"
  type        = number
  default     = 5
}

variable "dlq_depth_threshold" {
  description = "DLQ message count threshold for CloudWatch alarms"
  type        = number
  default     = 10
}

variable "monitor_all_regions" {
  description = "Monitor S3 events across all regions"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_s3_data_events" {
  description = "Enable CloudTrail S3 data events (increases cost)"
  type        = bool
  default     = false
}

variable "allowed_public_buckets" {
  description = "List of bucket names that are allowed to be public (e.g., CDN origins)"
  type        = list(string)
  default     = []
}

variable "slack_channel" {
  description = "Slack channel name for alerts"
  type        = string
  default     = "#security-alerts"
}

variable "enable_vpc" {
  description = "Deploy Lambda in VPC for enhanced security"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID for Lambda deployment (required if enable_vpc is true)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda deployment (required if enable_vpc is true)"
  type        = list(string)
  default     = []
}
