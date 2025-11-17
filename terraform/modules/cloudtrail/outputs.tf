output "trail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "trail_id" {
  description = "ID of the CloudTrail trail"
  value       = aws_cloudtrail.main.id
}
