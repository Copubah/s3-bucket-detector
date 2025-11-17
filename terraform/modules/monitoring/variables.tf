variable "project_name" {
  description = "Project name"
  type        = string
}

variable "lambda_function_name" {
  description = "Name of the Lambda function to monitor"
  type        = string
}

variable "sqs_queue_name" {
  description = "Name of the SQS queue"
  type        = string
}

variable "dlq_name" {
  description = "Name of the dead letter queue"
  type        = string
}

variable "sns_alert_email" {
  description = "Email address for SNS alerts"
  type        = string
}

variable "error_rate_threshold" {
  description = "Error rate threshold for alarms"
  type        = number
  default     = 5
}

variable "dlq_depth_threshold" {
  description = "DLQ depth threshold for alarms"
  type        = number
  default     = 10
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
