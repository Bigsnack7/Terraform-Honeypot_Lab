variable "name_prefix" { type = string }
variable "subnet_id" { type = string }
variable "security_group_id" { type = string }
variable "instance_profile_name" { type = string }
variable "instance_type" { type = string }
variable "cloudwatch_agent_version" {
  type = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+[a-z][0-9]+$", var.cloudwatch_agent_version))
    error_message = "cloudwatch_agent_version must be a versioned CloudWatch Agent release identifier."
  }
}
variable "cloudwatch_agent_msi_sha256" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.cloudwatch_agent_msi_sha256))
    error_message = "cloudwatch_agent_msi_sha256 must be a reviewed 64-character SHA-256 digest."
  }
}
variable "security_log_group_name" { type = string }
variable "system_log_group_name" { type = string }
variable "sysmon_log_group_name" { type = string }
variable "powershell_log_group_name" { type = string }
variable "health_log_group_name" { type = string }
