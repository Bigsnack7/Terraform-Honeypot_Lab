output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.audit.id
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
