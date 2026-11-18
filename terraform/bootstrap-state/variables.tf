variable "aws_region" {
  description = "Region for the Terraform state bucket."
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name dedicated to Terraform state."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid 3-63 character lowercase S3 bucket name."
  }
}

variable "allowed_account_ids" {
  description = "Optional AWS account allowlist for provider safety."
  type        = list(string)
  default     = []
}
