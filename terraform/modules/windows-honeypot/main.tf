data "aws_ami" "windows_server_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  cloudwatch_agent_config = jsonencode({
    logs = {
      logs_collected = {
        files = {
          collect_list = [
            {
              file_path       = "C:\\ProgramData\\Honeypot\\health.json"
              log_group_name  = var.health_log_group_name
              log_stream_name = "{instance_id}"
            }
          ]
        }
        windows_events = {
          collect_list = [
            {
              event_name      = "Security"
              event_ids       = [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4719, 4720, 4728, 4732, 4733, 4740, 1102]
              event_format    = "xml"
              log_group_name  = var.security_log_group_name
              log_stream_name = "{instance_id}"
            },
            {
              event_name      = "System"
              event_ids       = [104, 7045]
              event_format    = "xml"
              log_group_name  = var.system_log_group_name
              log_stream_name = "{instance_id}"
            },
            {
              event_name      = "Microsoft-Windows-Sysmon/Operational"
              event_ids       = [1, 3, 11, 13, 22]
              event_format    = "xml"
              log_group_name  = var.sysmon_log_group_name
              log_stream_name = "{instance_id}"
            },
            {
              event_name      = "Microsoft-Windows-PowerShell/Operational"
              event_ids       = [4104]
              event_format    = "xml"
              log_group_name  = var.powershell_log_group_name
              log_stream_name = "{instance_id}"
            }
          ]
        }
      }
    }
  })
}

resource "aws_instance" "windows" {
  lifecycle {
    ignore_changes = [ami]
  }

  ami                         = data.aws_ami.windows_server_2022.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.security_group_id]
  associate_public_ip_address = true
  iam_instance_profile        = var.instance_profile_name
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user-data.ps1.tftpl", {
    cloudwatch_agent_version    = var.cloudwatch_agent_version
    cloudwatch_agent_config     = local.cloudwatch_agent_config
    cloudwatch_agent_msi_sha256 = lower(var.cloudwatch_agent_msi_sha256)
    health_log_group_name       = var.health_log_group_name
    sysmon_config               = file("${path.module}/sysmon-config.xml")
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 30
    delete_on_termination = true
  }

  tags = {
    Name     = "${var.name_prefix}-windows-rdp"
    Honeypot = "windows"
  }
}
