output "vpc_ids" {
  value = { for name, resource in aws_vpc.honeypot : name => resource.id }
}

output "subnet_ids" {
  value = { for name, resource in aws_subnet.honeypot : name => resource.id }
}

output "security_group_ids" {
  value = { for name, resource in aws_security_group.honeypot : name => resource.id }
}
