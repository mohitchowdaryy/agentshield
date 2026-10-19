# AgentShield Terraform lab: INTENTIONALLY INSECURE.
#
# These resources exist only to be scanned by Checkov. They are never deployed: AgentShield does
# not run `terraform init`, `plan` or `apply`, and no cloud credentials are used.
# The fixed versions of the same resources are in ../secure/main.tf.

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

# --- Publicly exposed storage -------------------------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket = "agentshield-lab-reports"
}

# Block Public Access explicitly disabled.
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Bucket policy granting read access to everyone.
resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::agentshield-lab-reports/*"
    }]
  })
}

# --- Overly permissive network access -----------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "agentshield-lab-app"
  description = "Lab application security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All traffic to anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Broad IAM permissions ----------------------------------------------------------------------

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

# Full administrator access: every action on every resource.
resource "aws_iam_policy" "app" {
  name = "agentshield-lab-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app.arn
}
