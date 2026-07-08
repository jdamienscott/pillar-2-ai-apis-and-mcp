# 9a_bedrock_api/terraform/iam.tf
# Scoped, named-model-only IAM policy. No bedrock:* and no Resource:*.
# The Chapter 5 PermissionBoundary still applies underneath.

data "aws_iam_policy" "workload_boundary" {
  name = "ai-security-workload-boundary"  # from Ch 5 baseline
}

resource "aws_iam_role" "bedrock_api" {
  name                 = "pillar-2-bedrock-api"
  permissions_boundary = data.aws_iam_policy.workload_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "bedrock_invoke" {
  name        = "pillar-2-bedrock-invoke"
  description = "Named-model-only Bedrock policy; region-constrained"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      # Named model ARNs only — NOT Resource:"*"
      Resource = [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-*",
      ]
      Condition = {
        StringEquals = { "aws:RequestedRegion" = "us-east-1" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_api" {
  role       = aws_iam_role.bedrock_api.name
  policy_arn = aws_iam_policy.bedrock_invoke.arn
}

# Learning cap: $5/month. Production sizing in budget-sizing page.
resource "aws_budgets_budget" "per_key_cost_cap" {
  name         = "pillar-2-api-cost-cap"
  budget_type  = "COST"
  limit_amount = "5"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["Project$pillar-2"]
  }

  dynamic "notification" {
    for_each = [50, 80, 100, 200]
    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = notification.value
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [var.alerts_sns_topic_arn]
    }
  }
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN from the Chapter 5 baseline"
  type        = string
}
