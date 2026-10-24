# forbid: TG-TF-002
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}
module "git_tag" {
  source = "git::https://github.com/org/mod.git?ref=v1.2.0"
}
module "local" {
  source = "./modules/net"
}
