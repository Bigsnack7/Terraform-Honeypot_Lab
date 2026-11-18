variable "aws_region" { type = string }
variable "environment" { type = string }
variable "vpc_cidr" { type = string }
variable "availability_zone" { type = string }
variable "honeypot_ingress_cidrs" { type = list(string) }
variable "enable_windows_honeypot" { type = bool }
variable "enable_linux_honeypot" { type = bool }
variable "enable_web_honeypot" { type = bool }
variable "enable_smb_listener" { type = bool }
variable "enable_guardduty" { type = bool }
variable "enable_security_hub" { type = bool }
variable "enable_aws_config" { type = bool }
variable "enable_budget" { type = bool }
variable "budget_alert_email" { type = string }
variable "budget_limit_usd" { type = number }
variable "alert_email" { type = string }
variable "log_retention_days" { type = number }
variable "audit_log_retention_days" { type = number }
variable "linux_instance_type" { type = string }
variable "web_instance_type" { type = string }
variable "windows_instance_type" { type = string }
variable "cloudwatch_agent_version" { type = string }
variable "cloudwatch_agent_msi_sha256" { type = string }
variable "cowrie_version" { type = string }
variable "flask_version" { type = string }
variable "enable_ssm_management" { type = bool }

variable "query_definitions" {
  description = "Version-controlled CloudWatch Logs Insights queries."
  type = map(object({
    query_string    = string
    log_group_names = list(string)
  }))
}
