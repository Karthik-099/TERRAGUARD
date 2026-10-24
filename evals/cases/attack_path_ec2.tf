# expect: TG-PATH-003
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "app" {
  name = "app"
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_instance_profile" "app" {
  role = aws_iam_role.app.name
}
resource "aws_instance" "web" {
  ami                    = "ami-1"
  iam_instance_profile   = aws_iam_instance_profile.app.name
  vpc_security_group_ids = [aws_security_group.web.id]
}
