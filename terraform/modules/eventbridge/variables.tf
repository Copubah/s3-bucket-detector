variable "project_name" {
  description = "Project name"
  type        = string
}

variable "sqs_queue_arn" {
  description = "ARN of the SQS queue to send events to"
  type        = string
}

variable "enable_all_regions" {
  description = "Enable monitoring across all regions"
  type        = bool
  default     = true
}

variable "enable_config_integration" {
  description = "Enable AWS Config integration"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
