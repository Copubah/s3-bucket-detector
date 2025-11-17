variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "reports_bucket_name" {
  description = "Name for the reports S3 bucket"
  type        = string
}

variable "lambda_bucket_name" {
  description = "Name for the Lambda deployment S3 bucket"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
