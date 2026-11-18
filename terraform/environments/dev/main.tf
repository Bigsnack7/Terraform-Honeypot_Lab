locals {
  name_prefix = "honeypot-soc-${var.environment}"

  instance_ids = merge(
    var.enable_linux_honeypot ? { linux = module.linux_honeypot[0].instance_id } : {},
    var.enable_web_honeypot ? { web = module.web_honeypot[0].instance_id } : {},
    var.enable_windows_honeypot ? { windows = module.windows_honeypot[0].instance_id } : {}
  )

  public_ips = merge(
    var.enable_linux_honeypot ? { linux = module.linux_honeypot[0].public_ip } : {},
    var.enable_web_honeypot ? { web = module.web_honeypot[0].public_ip } : {},
    var.enable_windows_honeypot ? { windows = module.windows_honeypot[0].public_ip } : {}
  )
}

module "networking" {
  source = "../../modules/networking"

  name_prefix             = local.name_prefix
  vpc_cidr                = var.vpc_cidr
  availability_zone       = var.availability_zone
  honeypot_ingress_cidrs  = var.honeypot_ingress_cidrs
  enable_windows_honeypot = var.enable_windows_honeypot
  enable_linux_honeypot   = var.enable_linux_honeypot
  enable_web_honeypot     = var.enable_web_honeypot
  enable_smb_listener     = var.enable_smb_listener
}

module "monitoring" {
  source = "../../modules/monitoring"

  name_prefix        = local.name_prefix
  environment        = var.environment
  aws_region         = var.aws_region
  log_retention_days = var.log_retention_days
  query_definitions  = var.query_definitions
}

module "iam" {
  source = "../../modules/iam"

  name_prefix           = local.name_prefix
  log_group_arns        = module.monitoring.log_group_arns
  enable_ssm_management = var.enable_ssm_management
}

module "linux_honeypot" {
  source = "../../modules/linux-honeypot"
  count  = var.enable_linux_honeypot ? 1 : 0

  name_prefix           = local.name_prefix
  subnet_id             = module.networking.subnet_ids.linux
  security_group_id     = module.networking.security_group_ids.linux
  instance_profile_name = module.iam.instance_profile_name
  instance_type         = var.linux_instance_type
  cowrie_version        = var.cowrie_version
  cowrie_log_group_name = module.monitoring.log_group_names.linux_cowrie
  system_log_group_name = module.monitoring.log_group_names.linux_system
  health_log_group_name = module.monitoring.log_group_names.health_linux
}

module "web_honeypot" {
  source = "../../modules/web-honeypot"
  count  = var.enable_web_honeypot ? 1 : 0

  name_prefix           = local.name_prefix
  subnet_id             = module.networking.subnet_ids.web
  security_group_id     = module.networking.security_group_ids.web
  instance_profile_name = module.iam.instance_profile_name
  instance_type         = var.web_instance_type
  flask_version         = var.flask_version
  access_log_group_name = module.monitoring.log_group_names.web_access
  system_log_group_name = module.monitoring.log_group_names.web_system
  health_log_group_name = module.monitoring.log_group_names.health_web
}

module "windows_honeypot" {
  source = "../../modules/windows-honeypot"
  count  = var.enable_windows_honeypot ? 1 : 0

  name_prefix                 = local.name_prefix
  subnet_id                   = module.networking.subnet_ids.windows
  security_group_id           = module.networking.security_group_ids.windows
  instance_profile_name       = module.iam.instance_profile_name
  instance_type               = var.windows_instance_type
  cloudwatch_agent_version    = var.cloudwatch_agent_version
  cloudwatch_agent_msi_sha256 = var.cloudwatch_agent_msi_sha256
  security_log_group_name     = module.monitoring.log_group_names.windows_security
  system_log_group_name       = module.monitoring.log_group_names.windows_system
  sysmon_log_group_name       = module.monitoring.log_group_names.windows_sysmon
  powershell_log_group_name   = module.monitoring.log_group_names.windows_powershell
  health_log_group_name       = module.monitoring.log_group_names.health_windows
}

module "security" {
  source = "../../modules/security"

  name_prefix              = local.name_prefix
  aws_region               = var.aws_region
  enable_guardduty         = var.enable_guardduty
  enable_security_hub      = var.enable_security_hub
  enable_aws_config        = var.enable_aws_config
  enable_budget            = var.enable_budget
  budget_alert_email       = var.budget_alert_email
  budget_limit_usd         = var.budget_limit_usd
  alert_email              = var.alert_email
  audit_log_retention_days = var.audit_log_retention_days
  health_log_groups = merge(
    var.enable_linux_honeypot ? { linux = module.monitoring.log_group_names.health_linux } : {},
    var.enable_web_honeypot ? { web = module.monitoring.log_group_names.health_web } : {},
    var.enable_windows_honeypot ? { windows = module.monitoring.log_group_names.health_windows } : {}
  )
  instance_ids = local.instance_ids
}
