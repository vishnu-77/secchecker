# demo/terraform/main.tf — Intentionally misconfigured for secchecker demonstration.
# DO NOT apply this to a real environment.

provider "aws" {
  region = "us-east-1"
}

# [HIGH] Open security group — allows all inbound traffic from the internet
resource "aws_security_group" "open_to_world" {
  name = "demo-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# [HIGH] Public S3 bucket — bucket ACL exposes all objects to the internet
resource "aws_s3_bucket" "public_data" {
  bucket = "my-demo-public-bucket"
  acl    = "public-read"
}

# [CRITICAL] Hardcoded AWS credentials — secrets baked into infrastructure code
resource "aws_iam_access_key" "demo_key" {
  user = "demo-user"
}

locals {
  aws_access_key = "AKIAIOSFODNN7EXAMPLE"
  aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# [HIGH] RDS publicly accessible — database reachable from the internet
resource "aws_db_instance" "demo_db" {
  identifier        = "demo-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  publicly_accessible = true

  # [HIGH] Plaintext database password in Terraform config
  password = "supersecret123"
  username = "admin"
}
