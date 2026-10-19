# AgentShield Terraform lab: fixed versions of ../insecure/main.tf.
#
# Same resource names as the insecure file so scans can be compared check by check.
# Never deployed: AgentShield only scans these files with Checkov.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "vpc_id" {
  description = "VPC for the lab security group (placeholder; never applied)"
  type        = string
  default     = "vpc-0123456789abcdef0"
}

variable "internal_cidr" {
  description = "Only network allowed to reach the application"
  type        = string
  default     = "10.20.0.0/16"
}

# --- Storage: private, encrypted, versioned -----------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "reports" {
  description             = "Encryption key for the lab reports bucket"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  # Explicit key policy: only the owning account administers the key.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "reports" {
  bucket = "agentshield-lab-reports"
}

# Fix: all four Block Public Access settings enabled.
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Fix: no public principal; the policy only denies requests that do not use TLS.
resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        "arn:aws:s3:::agentshield-lab-reports",
        "arn:aws:s3:::agentshield-lab-reports/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.reports.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- Network: only HTTPS from the internal network ----------------------------------------------

# Fix: no SSH or RDP from the internet; HTTPS only from the internal CIDR, egress limited to HTTPS.
resource "aws_security_group" "app" {
  name        = "agentshield-lab-app"
  description = "Lab application security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from the internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.internal_cidr]
  }

  egress {
    description = "HTTPS to the internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.internal_cidr]
  }
}

# --- IAM: least privilege -----------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "agentshield-lab-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Fix: read-only access to the one bucket the application needs.
resource "aws_iam_policy" "app" {
  name = "agentshield-lab-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::agentshield-lab-reports",
        "arn:aws:s3:::agentshield-lab-reports/*",
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app.arn
}
