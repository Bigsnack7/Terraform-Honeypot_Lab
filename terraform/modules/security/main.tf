data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  audit_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}-audit"
  trail_name        = "${var.name_prefix}-management-trail"
  health_namespaces = {
    for name in keys(var.health_log_groups) : name => "Honeypot/${var.name_prefix}/health/${name}"
  }
}

resource "aws_s3_bucket" "audit" {
  bucket        = local.audit_bucket_name
  force_destroy = false

  tags = {
    Name        = local.audit_bucket_name
    DataPurpose = "CloudTrailAndOptionalConfig"
  }
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "expire-audit-objects"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = var.audit_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.audit_log_retention_days
    }
  }
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "CloudTrailBucketAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"]
    }
  }

  statement {
    sid    = "CloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_aws_config ? [1] : []

    content {
      sid    = "ConfigBucketAclCheck"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
      resources = [aws_s3_bucket.audit.arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_aws_config ? [1] : []

    content {
      sid    = "ConfigWrite"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.audit.arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket.json
}

resource "aws_cloudtrail" "management" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.audit.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }

  depends_on = [aws_s3_bucket_policy.audit]

  tags = {
    Name = local.trail_name
  }
}

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid    = "AllowEventBridgePublishFromLabRules"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${var.name_prefix}-*"]
    }
  }

  statement {
    sid    = "AllowCloudWatchAlarmPublishFromLab"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${var.name_prefix}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

resource "aws_budgets_budget" "monthly" {
  count = var.enable_budget ? 1 : 0

  name         = "${var.name_prefix}-monthly-spend"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 80, 100]

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.budget_alert_email]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}

resource "aws_guardduty_detector" "this" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  tags = {
    Name = "${var.name_prefix}-guardduty"
  }
}

resource "aws_securityhub_account" "this" {
  count                     = var.enable_security_hub ? 1 : 0
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"

  depends_on = [aws_guardduty_detector.this]
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  count = var.enable_guardduty ? 1 : 0
  name  = "${var.name_prefix}-guardduty-findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name = "${var.name_prefix}-guardduty-findings"
  }
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty[0].name
  target_id = "honeypot-alerts"
  arn       = aws_sns_topic.alerts.arn

  depends_on = [aws_sns_topic_policy.alerts]
}

resource "aws_cloudwatch_event_rule" "security_hub" {
  count = var.enable_security_hub ? 1 : 0
  name  = "${var.name_prefix}-security-hub-findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "security_hub" {
  count     = var.enable_security_hub ? 1 : 0
  rule      = aws_cloudwatch_event_rule.security_hub[0].name
  target_id = "honeypot-alerts"
  arn       = aws_sns_topic.alerts.arn

  depends_on = [aws_sns_topic_policy.alerts]
}

resource "aws_cloudwatch_event_rule" "config_compliance" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-config-compliance-changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
  })
}

resource "aws_cloudwatch_event_target" "config_compliance" {
  count     = var.enable_aws_config ? 1 : 0
  rule      = aws_cloudwatch_event_rule.config_compliance[0].name
  target_id = "honeypot-alerts"
  arn       = aws_sns_topic.alerts.arn

  depends_on = [aws_sns_topic_policy.alerts]
}

data "aws_iam_policy_document" "config_assume_role" {
  count = var.enable_aws_config ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_aws_config ? 1 : 0
  name               = "${var.name_prefix}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role[0].json
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.audit.id
  s3_key_prefix  = "config"

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.audit
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.this,
    aws_iam_role_policy_attachment.config
  ]
}

resource "aws_cloudwatch_log_metric_filter" "health" {
  for_each = var.health_log_groups

  name           = "${var.name_prefix}-${each.key}-heartbeat"
  log_group_name = each.value
  pattern        = "{ $.status = \"healthy\" }"

  metric_transformation {
    name          = "HealthyHeartbeat"
    namespace     = local.health_namespaces[each.key]
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "health" {
  for_each = var.health_log_groups

  alarm_name          = "${var.name_prefix}-${each.key}-heartbeat-missing"
  alarm_description   = "No healthy service heartbeat was observed for ${each.key}; inspect the host, service, and CloudWatch Agent."
  namespace           = local.health_namespaces[each.key]
  metric_name         = "HealthyHeartbeat"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.health]
}

resource "aws_cloudwatch_metric_alarm" "ec2_status" {
  for_each = var.instance_ids

  alarm_name          = "${var.name_prefix}-${each.key}-ec2-status-failed"
  alarm_description   = "EC2 instance status check failed for ${each.key}."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  dimensions          = { InstanceId = each.value }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
