# expect: TG-AWS-EKS-001
resource "aws_eks_cluster" "c" {
  name     = "prod"
  role_arn = "arn:aws:iam::1:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1"]
  }
}
