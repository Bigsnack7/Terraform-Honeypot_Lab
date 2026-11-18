output "state_bucket_name" {
  description = "Use this bucket in the lab backend configuration."
  value       = aws_s3_bucket.state.id
}
