# GitHub Actions OIDC trust for Terraform-Honeypot_Lab (draft, review before applying)
# Requires AWS provider >= 5.81 (thumbprint_list is optional there; AWS validates GitHub's cert itself).

variable "github_repo" {
  description = "GitHub repo allowed to assume the roles, as OWNER/REPO"
  type        = string
  default     = "Bigsnack7/Terraform-Honeypot_Lab"
}

# Jobs that declare `environment: NAME` get sub = repo:OWNER/REPO:environment:NAME
# (no branch in the claim), so branch protection must be enforced on the GitHub
# environment itself (deployment branches + required reviewers).
variable "plan_subs" {
  description = "OIDC sub claims allowed to assume the plan role (terraform-destroy.yml and terraform-plan-apply.yml)"
  type        = list(string)
  default = [
    "repo:Bigsnack7@287245995/Terraform-Honeypot_Lab@1463093635:environment:terraform-plan",
  ]
}

variable "apply_subs" {
  description = "OIDC sub claims allowed to assume the apply role (terraform-apply.yml and terraform-destroy-apply.yml)"
  type        = list(string)
  default = [
    "repo:Bigsnack7@287245995/Terraform-Honeypot_Lab@1463093635:environment:terraform-apply",
    "repo:Bigsnack7@287245995/Terraform-Honeypot_Lab@1463093635:environment:terraform-destroy",
  ]
}

variable "state_bucket_name" {
  description = "S3 bucket holding Terraform state (the TF_STATE_BUCKET value)"
  type        = string
}

variable "state_key" {
  type    = string
  default = "honeypot-soc/dev.tfstate"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

# ---------- Plan role: read-only, may be assumed from PRs and main ----------
data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.plan_subs
    }
  }
}

resource "aws_iam_role" "github_plan" {
  name                 = "honeypot-soc-dev-github-plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "github_plan_readonly" {
  role       = aws_iam_role.github_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Plan reads state and, with use_lockfile=true, must create/delete the .tflock object.
data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "ListStatePrefix"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.state_bucket_name}"]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = [var.state_key, "${var.state_key}.tflock"]
    }
  }
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.state_bucket_name}/${var.state_key}"]
  }
  statement {
    sid       = "LockFileOnly"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.state_bucket_name}/${var.state_key}.tflock"]
  }
}

resource "aws_iam_role_policy" "github_plan_state" {
  name   = "tf-state-read-lock"
  role   = aws_iam_role.github_plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

# ---------- Apply role: main branch (or one environment) only ----------
data "aws_iam_policy_document" "apply_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.apply_subs
    }
  }
}

resource "aws_iam_role" "github_apply" {
  name                 = "honeypot-soc-dev-github-apply"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

# Deliberately no permissions attached yet. Add a scoped policy built from the
# resource types in this repo; do NOT attach AdministratorAccess or PowerUserAccess.

output "github_plan_role_arn" {
  value = aws_iam_role.github_plan.arn
}

output "github_apply_role_arn" {
  value = aws_iam_role.github_apply.arn
}
