# This Terraform script provides an example of how to remediate a non-compliant S3 bucket.
# It enforces public access blocking and default encryption.

# To use this script, replace the bucket name with the name of the bucket you want to remediate.
variable "bucket_name" {
  description = "The name of the S3 bucket to remediate."
  type        = string
}

resource "aws_s3_bucket_public_access_block" "remediation" {
  bucket = var.bucket_name

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {
  bucket = var.bucket_name

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
