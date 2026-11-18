locals {
  query_directory = "${path.module}/../detections/cloudwatch-logs-insights"

  query_log_groups = {
    cowrie-ssh-brute-force        = ["/honeypot/${var.environment}/linux/cowrie"]
    cowrie-command-execution      = ["/honeypot/${var.environment}/linux/cowrie"]
    cowrie-post-exploitation      = ["/honeypot/${var.environment}/linux/cowrie"]
    windows-rdp-brute-force       = ["/honeypot/${var.environment}/windows/security"]
    windows-suspicious-powershell = ["/honeypot/${var.environment}/windows/powershell", "/honeypot/${var.environment}/windows/sysmon"]
    windows-admin-activity        = ["/honeypot/${var.environment}/windows/security"]
    windows-privilege-escalation  = ["/honeypot/${var.environment}/windows/security", "/honeypot/${var.environment}/windows/system"]
    windows-event-log-clearing    = ["/honeypot/${var.environment}/windows/security", "/honeypot/${var.environment}/windows/system"]
    web-path-scanning             = ["/honeypot/${var.environment}/web/access"]
  }

  query_definitions = {
    for file_name in fileset(local.query_directory, "*.sql") :
    trimsuffix(file_name, ".sql") => {
      query_string    = file("${local.query_directory}/${file_name}")
      log_group_names = local.query_log_groups[trimsuffix(file_name, ".sql")]
    }
  }
}
