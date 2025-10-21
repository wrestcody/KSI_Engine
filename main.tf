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

resource "aws_sqs_queue" "remediation_trigger_queue" {
  name = "remediation_trigger_queue"
}

data "aws_iam_policy_document" "lambda_policy" {
  # Required for CloudWatch logging
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Required for S3 compliance checks
  statement {
    actions = [
      "s3:ListAllMyBuckets"
    ]
    resources = ["arn:aws:s3:::*"]
  }

  statement {
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketEncryption"
    ]
    resources = ["arn:aws:s3:::*"]
  }

  # Required for triggering remediation
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.remediation_trigger_queue.arn]
  }
}

resource "aws_iam_policy" "lambda_policy" {
  name   = "lambda_s3_sqs_policy"
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_policy.arn
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

  environment {
    variables = {
      VANGUARD_AGENT_API_URL = var.vanguard_agent_api_url
      VANGUARD_API_KEY       = var.vanguard_api_key
      SQS_QUEUE_URL          = aws_sqs_queue.remediation_trigger_queue.id
    }
  }
}

resource "aws_cloudwatch_event_rule" "every_three_days" {
  name                = "every-three-days"
  description         = "Fires a scheduled event every three days to trigger the S3 compliance checker."
  schedule_expression = "rate(3 days)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.every_three_days.name
  target_id = "S3ComplianceChecker"
  arn       = aws_lambda_function.s3_compliance_checker.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_compliance_checker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.every_three_days.arn
}
