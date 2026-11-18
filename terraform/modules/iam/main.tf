data "aws_partition" "current" {}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "instance_logs" {
  statement {
    sid       = "WriteOnlyToLabLogGroups"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = [for arn in values(var.log_group_arns) : "${arn}:*"]
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name_prefix}-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.name_prefix}-instance"
  }
}

resource "aws_iam_role_policy" "instance_logs" {
  name   = "${var.name_prefix}-cloudwatch-logs"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_logs.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enable_ssm_management ? 1 : 0
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-instance"
  role = aws_iam_role.instance.name

  tags = {
    Name = "${var.name_prefix}-instance"
  }
}
