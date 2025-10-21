provider "aws" {
  region = "us-east-1"
}

data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

data "aws_iam_policy_document" "lambda_s3_policy" {
  statement {
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketEncryption"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "lambda_s3_policy" {
  name   = "lambda_s3_policy"
  policy = data.aws_iam_policy_document.lambda_s3_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_s3_policy_attachment" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

data "archive_file" "zip_python_code" {
  type        = "zip"
  source_file = "compliance_checker.py"
  output_path = "compliance_checker.zip"
}

resource "aws_lambda_function" "s3_compliance_checker" {
  filename         = data.archive_file.zip_python_code.output_path
  function_name    = "s3_compliance_checker"
  role             = aws_iam_role.iam_for_lambda.arn
  handler          = "compliance_checker.lambda_handler"
  runtime          = "python3.8"
  timeout          = 60
  source_code_hash = data.archive_file.zip_python_code.output_base64sha256
}
