resource "aws_s3_bucket" "tax" { acl = "public-read" }
resource "aws_db_instance" "db" { storage_encrypted = false
  publicly_accessible = true }
resource "aws_security_group_rule" "ssh" { cidr_blocks = ["0.0.0.0/0"] }
data "aws_iam_policy_document" "p" { statement { actions = ["*"]
  resources = ["*"] } }
