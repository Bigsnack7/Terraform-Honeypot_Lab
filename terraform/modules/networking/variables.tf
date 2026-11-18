variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "availability_zone" { type = string }
variable "honeypot_ingress_cidrs" { type = list(string) }
variable "enable_windows_honeypot" { type = bool }
variable "enable_linux_honeypot" { type = bool }
variable "enable_web_honeypot" { type = bool }
variable "enable_smb_listener" { type = bool }
