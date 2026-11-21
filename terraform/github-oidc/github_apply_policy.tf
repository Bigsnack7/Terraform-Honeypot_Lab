# Scoped permissions for honeypot-soc-dev-github-apply (draft, first iteration)
# Built from the resource types found in this repo. Expect a few AccessDenied
# errors on the first run; add only what CloudTrail shows is actually needed.

data "aws_caller_identity" "current" {}

locals {
  acct   = data.aws_caller_identity.current.account_id
  region = "us-east-1"
  prefix = "honeypot-soc-dev"
}

data "aws_iam_policy_document" "apply" {

  # EC2 / VPC: most EC2 actions don't support resource-level scoping, so lock to one region.
  statement {
    sid       = "Ec2VpcRegionLocked"
    actions   = ["ec2:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [local.region]
    }
  }

  # AMI lookups via public SSM parameters (remove if you pin AMI IDs)
  statement {
    sid       = "AmiParameterLookup"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:${local.region}::parameter/aws/service/*"]
  }

  # IAM: only roles and instance profiles with the lab prefix
  statement {
    sid = "IamLabRolesAndProfiles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:ListRoleTags",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile",
      "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
    ]
    resources = [
      "arn:aws:iam::${local.acct}:role/${local.prefix}-*",
      "arn:aws:iam::${local.acct}:instance-profile/${local.prefix}-*",
    ]
  }

  # Attaching managed policies is the main privilege-escalation path, so allow-list the ARNs.
  # VERIFY this list against the aws_iam_role_policy_attachment blocks in your Terraform.
  statement {
    sid       = "IamAttachAllowListedManagedPolicies"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = ["arn:aws:iam::${local.acct}:role/${local.prefix}-*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values = [
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
        "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
      ]
    }
  }

  statement {
    sid       = "PassLabRolesToExpectedServices"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.acct}:role/${local.prefix}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com", "config.amazonaws.com"]
    }
  }

  statement {
    sid       = "ServiceLinkedRolesForSecurityServices"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${local.acct}:role/aws-service-role/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "guardduty.amazonaws.com",
        "securityhub.amazonaws.com",
        "config.amazonaws.com",
        "cloudtrail.amazonaws.com",
      ]
    }
  }

  # S3: lab buckets only
  statement {
    sid     = "S3LabBuckets"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${local.prefix}-*",
      "arn:aws:s3:::${local.prefix}-*/*",
    ]
  }

  # Terraform state (this key only) and its lock file
  statement {
    sid       = "StateList"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.state_bucket_name}"]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = [var.state_key, "${var.state_key}.tflock"]
    }
  }
  statement {
    sid     = "StateReadWrite"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = [
      "arn:aws:s3:::${var.state_bucket_name}/${var.state_key}",
      "arn:aws:s3:::${var.state_bucket_name}/${var.state_key}.tflock",
    ]
  }

  # Logs have limited resource-level support for Describe/Query calls, so region-lock
  statement {
    sid       = "CloudWatchLogsRegionLocked"
    actions   = ["logs:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [local.region]
    }
  }

  statement {
    sid       = "SnsLabTopics"
    actions   = ["sns:*"]
    resources = ["arn:aws:sns:${local.region}:${local.acct}:${local.prefix}-*"]
  }

  statement {
    sid       = "EventBridgeLabRules"
    actions   = ["events:*"]
    resources = ["arn:aws:events:${local.region}:${local.acct}:rule/${local.prefix}-*"]
  }

  statement {
    sid       = "CloudWatchAlarmsLab"
    actions   = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource", "cloudwatch:ListTagsForResource"]
    resources = ["arn:aws:cloudwatch:${local.region}:${local.acct}:alarm:${local.prefix}-*"]
  }

  statement {
    sid       = "CloudWatchAlarmsRead"
    actions   = ["cloudwatch:DescribeAlarms"]
    resources = ["*"]
  }

  statement {
    sid       = "BudgetsInAccount"
    actions   = ["budgets:*"]
    resources = ["arn:aws:budgets::${local.acct}:budget/*"]
  }

  # Config, GuardDuty, Security Hub, CloudTrail: mostly account-level, region-lock only
  statement {
    sid       = "SecurityServicesRegionLocked"
    actions   = ["config:*", "guardduty:*", "securityhub:*", "cloudtrail:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [local.region]
    }
  }

  # The apply role must never be able to edit its own trust, the plan role, or the OIDC provider.
  statement {
    sid     = "DenyTouchingGithubTrust"
    effect  = "Deny"
    actions = ["iam:*"]
    resources = [
      "arn:aws:iam::${local.acct}:role/${local.prefix}-github-plan",
      "arn:aws:iam::${local.acct}:role/${local.prefix}-github-apply",
      "arn:aws:iam::${local.acct}:oidc-provider/token.actions.githubusercontent.com",
    ]
  }
}

resource "aws_iam_policy" "github_apply" {
  name   = "${local.prefix}-github-apply"
  policy = data.aws_iam_policy_document.apply.json
}

resource "aws_iam_role_policy_attachment" "github_apply" {
  role       = aws_iam_role.github_apply.name
  policy_arn = aws_iam_policy.github_apply.arn
}
