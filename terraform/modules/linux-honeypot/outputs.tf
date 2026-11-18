output "instance_id" {
  value = aws_instance.cowrie.id
}

output "public_ip" {
  value = aws_instance.cowrie.public_ip
}
