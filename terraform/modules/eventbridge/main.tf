data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# EventBridge rule to capture S3 bucket configuration changes
resource "aws_cloudwatch_event_rule" "s3_config_changes" {
  name        = "${var.project_name}-s3-config-changes"
  description = "Capture S3 bucket ACL and policy changes via CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutObjectAcl"
      ]
    }
  })

  tags = var.tags
}

# EventBridge target - SQS queue
resource "aws_cloudwatch_event_target" "sqs" {
  rule      = aws_cloudwatch_event_rule.s3_config_changes.name
  target_id = "SendToSQS"
  arn       = var.sqs_queue_arn

  retry_policy {
    maximum_event_age       = 3600  # 1 hour
    maximum_retry_attempts  = 3
  }

  dead_letter_config {
    arn = var.sqs_queue_arn
  }
}

# Additional rule for AWS Config changes (optional)
resource "aws_cloudwatch_event_rule" "config_changes" {
  count       = var.enable_config_integration ? 1 : 0
  name        = "${var.project_name}-config-changes"
  description = "Capture AWS Config compliance changes for S3 buckets"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [
        "s3-bucket-public-read-prohibited",
        "s3-bucket-public-write-prohibited"
      ]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "config_sqs" {
  count     = var.enable_config_integration ? 1 : 0
  rule      = aws_cloudwatch_event_rule.config_changes[0].name
  target_id = "SendToSQS"
  arn       = var.sqs_queue_arn
}
