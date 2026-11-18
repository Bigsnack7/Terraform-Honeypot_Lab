locals {
  decoys = {
    linux = {
      enabled = var.enable_linux_honeypot
      index   = 1
      ports   = [22]
    }
    web = {
      enabled = var.enable_web_honeypot
      index   = 2
      ports   = [80]
    }
    windows = {
      enabled = var.enable_windows_honeypot
      index   = 3
      ports   = concat([3389], var.enable_smb_listener ? [445] : [])
    }
  }

  ingress_rules = {
    for rule in flatten([
      for decoy, config in local.decoys : [
        for port in config.ports : [
          for cidr in var.honeypot_ingress_cidrs : {
            key   = "${decoy}-${port}-${replace(cidr, "/", "-")}"
            decoy = decoy
            port  = port
            cidr  = cidr
            label = decoy == "windows" && port == 3389 ? "RDP honeypot listener" : decoy == "windows" ? "Optional SMB decoy listener" : "${upper(decoy)} honeypot listener"
          }
        ]
      ] if config.enabled
    ]) : rule.key => rule
  }
}

resource "aws_vpc" "honeypot" {
  for_each = local.decoys

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  instance_tenancy     = "default"

  tags = {
    Name     = "${var.name_prefix}-${each.key}-vpc"
    Honeypot = each.key
  }
}

resource "aws_internet_gateway" "honeypot" {
  for_each = local.decoys
  vpc_id   = aws_vpc.honeypot[each.key].id

  tags = {
    Name     = "${var.name_prefix}-${each.key}-igw"
    Honeypot = each.key
  }
}

resource "aws_subnet" "honeypot" {
  for_each = local.decoys

  vpc_id                  = aws_vpc.honeypot[each.key].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value.index)
  availability_zone       = var.availability_zone == "" ? null : var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name     = "${var.name_prefix}-${each.key}-public"
    Honeypot = each.key
    Exposure = "Public-Honeypot-Only"
  }
}

resource "aws_route_table" "public" {
  for_each = local.decoys
  vpc_id   = aws_vpc.honeypot[each.key].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot[each.key].id
  }

  tags = {
    Name     = "${var.name_prefix}-${each.key}-public"
    Honeypot = each.key
  }
}

resource "aws_route_table_association" "public" {
  for_each       = local.decoys
  subnet_id      = aws_subnet.honeypot[each.key].id
  route_table_id = aws_route_table.public[each.key].id
}

resource "aws_security_group" "honeypot" {
  for_each = local.decoys

  name                   = "${var.name_prefix}-${each.key}-honeypot"
  description            = "Isolated ${each.key} honeypot listener; no administrative ingress."
  vpc_id                 = aws_vpc.honeypot[each.key].id
  revoke_rules_on_delete = true
  egress                 = []

  tags = {
    Name     = "${var.name_prefix}-${each.key}-honeypot"
    Honeypot = each.key
  }
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_listener" {
  for_each = local.ingress_rules

  security_group_id = aws_security_group.honeypot[each.value.decoy].id
  cidr_ipv4         = each.value.cidr
  from_port         = each.value.port
  to_port           = each.value.port
  ip_protocol       = "tcp"
  description       = "${each.value.label} from explicitly configured source"
}

resource "aws_vpc_security_group_egress_rule" "https" {
  for_each = local.decoys

  security_group_id = aws_security_group.honeypot[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS for CloudWatch, Systems Manager, and bootstrap packages; arbitrary TLS egress remains possible"
}
