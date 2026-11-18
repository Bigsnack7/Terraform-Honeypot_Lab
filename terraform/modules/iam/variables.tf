variable "name_prefix" { type = string }
variable "log_group_arns" { type = map(string) }
variable "enable_ssm_management" { type = bool }
