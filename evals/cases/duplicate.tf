# expect: TG-VAL-002, TG-VAL-007
resource "aws_sqs_queue" "q" {
  name = "a"
}
resource "aws_sqs_queue" "q" {
  count    = 1
  for_each = toset(["x"])
  name     = "b"
}
