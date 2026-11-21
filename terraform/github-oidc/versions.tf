terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81"
    }
  }

  # Local state on purpose: this root must NOT share state with the workflows'
  # honeypot-soc/dev.tfstate, or destroy-apply would try to delete its own role.
}

provider "aws" {
  region = "us-east-1"
}
