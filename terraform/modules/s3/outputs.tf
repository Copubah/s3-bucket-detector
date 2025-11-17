output "reports_bucket_id" {
  description = "ID of the reports bucket"
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the reports bucket"
  value       = aws_s3_bucket.reports.arn
}

output "lambda_bucket_id" {
  description = "ID of the Lambda deployment bucket"
  value       = aws_s3_bucket.lambda.id
}

output "lambda_bucket_arn" {
  description = "ARN of the Lambda deployment bucket"
  value       = aws_s3_bucket.lambda.arn
}

output "cloudtrail_bucket_id" {
  description = "ID of the CloudTrail bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail bucket"
  value       = aws_s3_bucket.cloudtrail.arn
}
