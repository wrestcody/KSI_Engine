# This Terraform script provides an example of how to remediate a non-compliant S3 bucket
# by enforcing default encryption.

variable "bucket_name" {
  description = "The name of the S3 bucket to remediate."
  type        = string
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {
  bucket = var.bucket_name

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
