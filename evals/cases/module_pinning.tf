# expect: TG-TF-002
module "unpinned" {
  source = "terraform-aws-modules/vpc/aws"
}
module "git_branch" {
  source = "git::https://github.com/org/mod.git"
}
