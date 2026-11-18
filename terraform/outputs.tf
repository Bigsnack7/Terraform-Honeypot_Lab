output "vpc_ids" {
  description = "Independent VPC IDs; decoys have no peering or shared network."
  value       = module.dev.vpc_ids
}

output "enabled_instance_ids" {
  description = "Instance IDs for enabled honeypots."
  value       = module.dev.instance_ids
}

output "public_ips" {
  description = "Public IPv4 addresses for enabled decoys. These are billable resources."
  value       = module.dev.public_ips
}

output "cloudtrail_bucket_name" {
  description = "Private S3 bucket receiving CloudTrail management events."
  value       = module.dev.cloudtrail_bucket_name
}
