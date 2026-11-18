output "vpc_ids" {
  value = module.networking.vpc_ids
}

output "instance_ids" {
  value = local.instance_ids
}

output "public_ips" {
  value = local.public_ips
}

output "cloudtrail_bucket_name" {
  value = module.security.cloudtrail_bucket_name
}
