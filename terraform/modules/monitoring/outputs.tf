output "log_group_names" {
  value = local.log_group_names
}

output "log_group_arns" {
  value = {
    for key, name in local.log_group_names :
    key => "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${name}"
  }
}
