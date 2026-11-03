package engine

import "testing"

const cfnYAML = `AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Encrypt:
    Type: String
    Default: "false"
  Retention:
    Type: Number
Globals:
  Function:
    Runtime: python3.7
Resources:
  Logs:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: !Ref Retention
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: mysql
      StorageEncrypted: !Ref Encrypt
      DBSubnetGroupName: !Ref Subnets
  Subnets:
    Type: AWS::RDS::DBSubnetGroup
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
`

func TestCloudFormationShape(t *testing.T) {
	rs, syntax := parseCloudFormation("t.yaml", cfnYAML)
	if len(syntax) > 0 || len(rs) != 4 {
		t.Fatalf("got %d resources, %v", len(rs), syntax)
	}
	by := map[string]*Resource{}
	for _, r := range rs {
		by[r.Name] = r
	}
	db := by["Db"]
	if db.Address != "AWS::RDS::DBInstance.Db" || db.Line != 16 || db.line("Properties.StorageEncrypted") != 20 {
		t.Errorf("db shape: %s line %d", db.Address, db.Line)
	}
	if v := db.get("Properties.StorageEncrypted"); v != "false" {
		t.Errorf("Ref should resolve to the parameter default, got %#v", v)
	}
	if len(db.Refs) != 1 || db.Refs[0] != "AWS::RDS::DBSubnetGroup.Subnets" {
		t.Errorf("refs %v", db.Refs)
	}
	if !isUnknown(by["Logs"].get("Properties.RetentionInDays")) {
		t.Error("Ref to a parameter without a default should be Unknown")
	}
	fn := by["Fn"]
	if fn.get("Properties.Runtime") != "python3.7" || fn.line("Properties.Runtime") != 10 {
		t.Errorf("Globals not applied: %v", fn.Attrs)
	}
}

func TestCloudFormationJSONIntrinsics(t *testing.T) {
	src := `{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
  "Q": {"Type": "AWS::SQS::Queue", "Properties": {"KmsMasterKeyId": {"Fn::GetAtt": ["Key", "Arn"]}, "QueueName": {"Ref": "AWS::NoValue"}}},
  "Key": {"Type": "AWS::KMS::Key", "Properties": {"EnableKeyRotation": {"Fn::If": ["C", true, false]}}}}}`
	rs, _ := parseCloudFormation("t.json", src)
	if len(rs) != 2 {
		t.Fatalf("got %d resources", len(rs))
	}
	q := rs[1]
	if !isUnknown(q.get("Properties.KmsMasterKeyId")) || q.get("Properties.QueueName") != nil || q.Line != 2 {
		t.Errorf("queue %v line %d", q.Attrs, q.Line)
	}
	if len(q.Refs) != 1 || q.Refs[0] != "AWS::KMS::Key.Key" {
		t.Errorf("refs %v", q.Refs)
	}
}

func TestCloudFormationRules(t *testing.T) {
	src := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Open:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  Dynamic:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: dynamic
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Ref Cidr
`
	rep := Scan(Input{Files: map[string]string{"sg.yaml": src}, Only: []string{"TG-CFN-SG-201"}})
	if len(rep.Findings) != 1 || rep.Findings[0].Resource != "AWS::EC2::SecurityGroup.Open" || rep.Findings[0].Line != 8 {
		t.Fatalf("findings %+v", rep.Findings)
	}
}

// AWS documentation's fake key, split so the secret scanner does not flag the source.
const fakeKey = "AKIA" + "IOSFODNN7EXAMPLE"

func TestServerlessShape(t *testing.T) {
	src := `service: svc
custom:
  key: ` + fakeKey + `
provider:
  name: aws
  runtime: python3.12
  environment:
    SHARED: x
  iamRoleStatements:
    - Effect: Allow
      Action: "*"
      Resource: "*"
functions:
  hello:
    handler: h.main
    environment:
      AWS_ACCESS_KEY_ID: ${self:custom.key}
      OTHER: ${env:OTHER}
resources:
  Resources:
    Bucket:
      Type: AWS::S3::Bucket
`
	rs, syntax := parseServerless("serverless.yml", src)
	if len(syntax) > 0 || len(rs) != 3 {
		t.Fatalf("got %d resources, %v", len(rs), syntax)
	}
	var fn *Resource
	for _, r := range rs {
		if r.Type == "serverless_function" {
			fn = r
		}
	}
	if fn == nil || fn.get("runtime") != "python3.12" || fn.get("environment.SHARED") != "x" || !isUnknown(fn.get("environment.OTHER")) {
		t.Fatalf("function %+v", fn)
	}
	if fn.get("environment.AWS_ACCESS_KEY_ID") != fakeKey || fn.line("iamRoleStatements.0") != 10 || fn.Line != 14 {
		t.Errorf("vars or lines: %v %v", fn.Attrs, fn.Lines)
	}
	rep := Scan(Input{Files: map[string]string{"serverless.yml": src}, Only: []string{"TG-SLS-IAM-201", "TG-SLS-LAMBDA-201"}})
	if len(rep.Findings) != 2 {
		t.Errorf("findings %+v", rep.Findings)
	}
}
