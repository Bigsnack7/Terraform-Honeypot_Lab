variable "aws_region" {
  description = "AWS region for the lab."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier."
  }
}

variable "allowed_account_ids" {
  description = "Optional AWS account allowlist for provider safety."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.allowed_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "Each allowed_account_ids entry must be a 12-digit AWS account ID."
  }
}

variable "environment" {
  description = "Environment name used in resource names and tags."
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,16}$", var.environment))
    error_message = "environment must be 1-16 lowercase letters, digits, or hyphens."
  }
}

variable "vpc_cidr" {
  description = "IPv4 CIDR range for the isolated honeypot VPC."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "availability_zone" {
  description = "Optional single availability zone; empty lets AWS select one."
  type        = string
  default     = ""
}

variable "honeypot_ingress_cidrs" {
  description = "Explicit IPv4 sources allowed to reach enabled decoy listener ports. Use 0.0.0.0/0 only when deliberately accepting global Internet exposure."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.honeypot_ingress_cidrs : can(cidrhost(cidr, 0))])
    error_message = "Every honeypot_ingress_cidrs entry must be a valid IPv4 CIDR."
  }
}

variable "enable_windows_honeypot" {
  description = "Create the Windows RDP honeypot. Windows compute and licensing may incur charges."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_windows_honeypot || length(var.honeypot_ingress_cidrs) > 0
    error_message = "Set honeypot_ingress_cidrs explicitly before enabling the Windows honeypot."
  }
}

variable "enable_linux_honeypot" {
  description = "Create the Linux Cowrie SSH honeypot."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_linux_honeypot || length(var.honeypot_ingress_cidrs) > 0
    error_message = "Set honeypot_ingress_cidrs explicitly before enabling the Linux honeypot."
  }
}

variable "enable_web_honeypot" {
  description = "Create the Flask web application decoy."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_web_honeypot || length(var.honeypot_ingress_cidrs) > 0
    error_message = "Set honeypot_ingress_cidrs explicitly before enabling the web honeypot."
  }
}

variable "enable_smb_listener" {
  description = "Also expose TCP 445 on the Windows decoy. Disabled by default."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Enable GuardDuty; usage-based charges may apply."
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Enable Security Hub; usage-based charges may apply."
  type        = bool
  default     = false
}

variable "enable_aws_config" {
  description = "Enable AWS Config recording and delivery; configuration-item charges may apply."
  type        = bool
  default     = false
}

variable "enable_budget" {
  description = "Create a low-threshold monthly AWS Budget alert."
  type        = bool
  default     = true
}

variable "budget_alert_email" {
  description = "Email address for AWS Budget notifications. Required while enable_budget is true."
  type        = string

  validation {
    condition     = !var.enable_budget || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_alert_email))
    error_message = "Set budget_alert_email to a valid address when enable_budget is true."
  }
}

variable "budget_limit_usd" {
  description = "Monthly budget alert threshold in USD. This does not cap or stop spending."
  type        = number
  default     = 5

  validation {
    condition     = var.budget_limit_usd > 0
    error_message = "budget_limit_usd must be greater than zero."
  }
}

variable "alert_email" {
  description = "Optional email subscription for CloudWatch and security-finding alerts."
  type        = string
  default     = ""

  validation {
    condition     = var.alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be empty or a valid email address."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a supported CloudWatch Logs retention value."
  }
}

variable "linux_instance_type" {
  description = "Linux instance size. Confirm account-specific Free Tier eligibility and Cowrie memory requirements."
  type        = string
  default     = "t3.micro"
}

variable "web_instance_type" {
  description = "Web decoy instance size. Confirm account-specific Free Tier eligibility."
  type        = string
  default     = "t3.micro"
}

variable "windows_instance_type" {
  description = "Windows instance size. Windows is disabled by default and may be costly."
  type        = string
  default     = "t3.small"
}

variable "cloudwatch_agent_version" {
  description = "Pinned version of the Windows CloudWatch Agent MSI."
  type        = string
  default     = "1.300074.1b2005"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+[a-z][0-9]+$", var.cloudwatch_agent_version))
    error_message = "cloudwatch_agent_version must be a versioned CloudWatch Agent release identifier."
  }
}

variable "cloudwatch_agent_msi_sha256" {
  description = "SHA-256 of the pinned Windows CloudWatch Agent MSI, verified against its valid Amazon Authenticode signature."
  type        = string
  default     = "3891c26f477cc47cf1b3965b18ffb25532b67e4534b60f692cb6605b6bee1577"

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.cloudwatch_agent_msi_sha256))
    error_message = "cloudwatch_agent_msi_sha256 must be a 64-character SHA-256 digest."
  }
}

variable "cowrie_version" {
  description = "Pinned Cowrie Python package version."
  type        = string
  default     = "2.5.0"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.cowrie_version))
    error_message = "cowrie_version must use a pinned semantic version."
  }
}

variable "flask_version" {
  description = "Pinned Flask Python package version."
  type        = string
  default     = "3.1.1"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.flask_version))
    error_message = "flask_version must use a pinned semantic version."
  }
}

variable "enable_ssm_management" {
  description = "Attach the standard SSM managed-instance policy for agent-based administration; no inbound SSH/RDP management rule is created."
  type        = bool
  default     = true
}

variable "audit_log_retention_days" {
  description = "Lifecycle retention for CloudTrail and optional AWS Config S3 objects."
  type        = number
  default     = 90

  validation {
    condition     = var.audit_log_retention_days >= 30 && var.audit_log_retention_days <= 3650
    error_message = "audit_log_retention_days must be between 30 and 3650."
  }
}
