data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# SNS topic for alarms
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-alerts"
  display_name      = "S3 Bucket Detector Alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.sns_alert_email
}

# CloudWatch metric filter for detections
resource "aws_cloudwatch_log_metric_filter" "public_bucket_detected" {
  name           = "${var.project_name}-public-bucket-detected"
  log_group_name = "/aws/lambda/${var.lambda_function_name}"
  pattern        = "[time, request_id, level=INFO, msg=\"Public bucket detected\", ...]"

  metric_transformation {
    name      = "PublicBucketsDetected"
    namespace = "S3BucketDetector"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "remediation_performed" {
  name           = "${var.project_name}-remediation-performed"
  log_group_name = "/aws/lambda/${var.lambda_function_name}"
  pattern        = "[time, request_id, level=INFO, msg=\"Remediation performed\", ...]"

  metric_transformation {
    name      = "RemediationsPerformed"
    namespace = "S3BucketDetector"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "slack_notification_failed" {
  name           = "${var.project_name}-slack-failed"
  log_group_name = "/aws/lambda/${var.lambda_function_name}"
  pattern        = "[time, request_id, level=ERROR, msg=\"Slack notification failed\", ...]"

  metric_transformation {
    name      = "SlackNotificationFailures"
    namespace = "S3BucketDetector"
    value     = "1"
    unit      = "Count"
  }
}

# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project_name}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = var.error_rate_threshold
  alarm_description   = "Lambda function error rate exceeded threshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = var.lambda_function_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "${var.project_name}-lambda-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Lambda function is being throttled"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = var.lambda_function_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${var.project_name}-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Average"
  threshold           = var.dlq_depth_threshold
  alarm_description   = "Dead letter queue has messages requiring attention"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = var.dlq_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "sqs_age" {
  alarm_name          = "${var.project_name}-sqs-message-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 600  # 10 minutes
  alarm_description   = "SQS messages are not being processed in time"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = var.sqs_queue_name
  }

  tags = var.tags
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.project_name

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["S3BucketDetector", "PublicBucketsDetected", { stat = "Sum", label = "Public Buckets Detected" }],
            [".", "RemediationsPerformed", { stat = "Sum", label = "Remediations Performed" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Detection and Remediation"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Invocations" }],
            [".", "Errors", { stat = "Sum", label = "Errors" }],
            [".", "Throttles", { stat = "Sum", label = "Throttles" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Lambda Performance"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", { stat = "Average", label = "Avg Duration" }],
            ["...", { stat = "Maximum", label = "Max Duration" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Lambda Duration (ms)"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", { stat = "Average", label = "Messages in Queue" }],
            [".", "ApproximateAgeOfOldestMessage", { stat = "Maximum", label = "Oldest Message Age (s)" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "SQS Queue Metrics"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", { stat = "Average", label = "DLQ Depth" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Dead Letter Queue"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "log"
        properties = {
          query   = "SOURCE '/aws/lambda/${var.lambda_function_name}' | fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 20"
          region  = data.aws_region.current.name
          title   = "Recent Errors"
        }
      }
    ]
  })
}
