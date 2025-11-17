output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = module.lambda.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = module.lambda.function_arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue"
  value       = aws_sqs_queue.detector_queue.url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue"
  value       = aws_sqs_queue.detector_queue.arn
}

output "dlq_url" {
  description = "URL of the dead letter queue"
  value       = aws_sqs_queue.detector_queue_dlq.url
}

output "reports_bucket_name" {
  description = "Name of the S3 bucket for reports"
  value       = module.s3_buckets.reports_bucket_id
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = module.s3_buckets.cloudtrail_bucket_id
}

output "slack_secret_arn" {
  description = "ARN of the Secrets Manager secret for Slack webhook"
  value       = aws_secretsmanager_secret.slack_webhook.arn
}

output "cloudwatch_dashboard_url" {
  description = "URL to CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${module.monitoring.dashboard_name}"
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = module.eventbridge.eventbridge_rule_arn
}

output "deployment_instructions" {
  description = "Next steps after Terraform apply"
  value       = <<-EOT
    
    ✅ Infrastructure deployed successfully!
    
    Next steps:
    
    1. Upload Lambda code:
       cd ../src
       ./build.sh
       aws s3 cp lambda.zip s3://${module.s3_buckets.lambda_bucket_id}/${var.lambda_s3_key}
    
    2. Set Slack webhook secret:
       aws secretsmanager put-secret-value \
         --secret-id ${aws_secretsmanager_secret.slack_webhook.name} \
         --secret-string '{"webhook_url":"https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}'
    
    3. Test the function:
       aws lambda invoke \
         --function-name ${module.lambda.function_name} \
         --payload file://test_event.json \
         response.json
    
    4. View logs:
       aws logs tail /aws/lambda/${module.lambda.function_name} --follow
    
    5. Monitor dashboard:
       ${module.monitoring.dashboard_url}
    
    6. Enable auto-remediation (optional):
       aws lambda update-function-configuration \
         --function-name ${module.lambda.function_name} \
         --environment Variables={AUTO_REMEDIATE=true}
  EOT
}
