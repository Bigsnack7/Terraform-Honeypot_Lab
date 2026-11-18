provider "aws" {
  region              = var.aws_region
  allowed_account_ids = length(var.allowed_account_ids) > 0 ? var.allowed_account_ids : null

  default_tags {
    tags = {
      Project            = "Honeypot-SOC-Lab"
      Environment        = var.environment
      ManagedBy          = "Terraform"
      DataClassification = "SecurityTelemetry"
    }
  }
}
