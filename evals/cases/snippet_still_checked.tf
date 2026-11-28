# path: examples/resources/aws_vpc/resource.tf
# expect: TG-VAL-002, TG-VAL-004
# Snippets keep value checks and duplicates inside one file.
resource "aws_vpc" "example" {
  cidr_block = "10.0.0.1/16"
}

resource "aws_vpc" "example" {
  cidr_block = "10.1.0.0/16"
}
