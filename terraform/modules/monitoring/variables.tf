variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "aws_region" { type = string }
variable "log_retention_days" { type = number }

variable "query_definitions" {
  type = map(object({
    query_string    = string
    log_group_names = list(string)
  }))
}
