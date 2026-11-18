data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  log_group_names = {
    linux_cowrie       = "/honeypot/${var.environment}/linux/cowrie"
    linux_system       = "/honeypot/${var.environment}/linux/system"
    web_access         = "/honeypot/${var.environment}/web/access"
    web_system         = "/honeypot/${var.environment}/web/system"
    windows_security   = "/honeypot/${var.environment}/windows/security"
    windows_system     = "/honeypot/${var.environment}/windows/system"
    windows_sysmon     = "/honeypot/${var.environment}/windows/sysmon"
    windows_powershell = "/honeypot/${var.environment}/windows/powershell"
    health_linux       = "/honeypot/${var.environment}/health/linux"
    health_web         = "/honeypot/${var.environment}/health/web"
    health_windows     = "/honeypot/${var.environment}/health/windows"
  }
}

resource "aws_cloudwatch_log_group" "honeypot" {
  for_each = local.log_group_names

  name              = each.value
  retention_in_days = var.log_retention_days

  tags = {
    Name     = each.value
    LogClass = "HoneypotTelemetry"
  }
}

resource "aws_cloudwatch_query_definition" "detections" {
  for_each = var.query_definitions

  name            = "/${var.environment}/honeypot/${each.key}"
  query_string    = each.value.query_string
  log_group_names = each.value.log_group_names
}
