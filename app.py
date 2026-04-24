from flask import Flask, request, jsonify, send_from_directory
from openai import OpenAI
import json
import os

app = Flask(__name__, static_folder="static")
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are TerraGuard, an expert AI security agent specializing in Terraform and Infrastructure-as-Code security analysis.

Analyze the provided Terraform code for security vulnerabilities, misconfigurations, and best practice violations.

For each issue found, return a JSON array with objects in this exact format:
{
  "id": "TG-001",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "title": "Short title of the issue",
  "resource": "The terraform resource affected (e.g. aws_s3_bucket.my_bucket)",
  "line_hint": "Approximate line or block where the issue is",
  "description": "Clear explanation of why this is a security issue",
  "fix": "Concrete Terraform code or configuration fix",
  "cwe": "CWE-ID if applicable, else null",
  "tags": ["array", "of", "relevant", "tags"]
}

Check for issues including but not limited to:
- Exposed secrets or hardcoded credentials
- Overly permissive IAM roles/policies (e.g. Action: *, Principal: *)
- Public S3 buckets or unencrypted storage
- Security groups open to 0.0.0.0/0 on sensitive ports
- Missing encryption at rest or in transit
- Disabled logging, monitoring, or CloudTrail
- Unencrypted EBS volumes or RDS instances
- Missing MFA delete on S3
- Public RDS instances
- Missing VPC flow logs
- Overprivileged Lambda execution roles
- Exposed ports (22, 3389, 5432, 3306, 6379, etc.)
- Missing resource tagging (INFO level)
- Insecure TLS versions

Return ONLY valid JSON array, no markdown, no explanation outside the array. If no issues found, return empty array [].
"""

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    tf_code = data.get("code", "").strip()

    if not tf_code:
        return jsonify({"error": "No Terraform code provided"}), 400

    if len(tf_code) > 50000:
        return jsonify({"error": "File too large (max 50KB)"}), 400

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this Terraform code for security issues:\n\n```hcl\n{tf_code}\n```"}
            ],
            temperature=0.1,
            max_tokens=4000
        )

        raw = response.choices[0].message.content.strip()

        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            raw = raw.rsplit("```", 1)[0]

        findings = json.loads(raw)

        # Count severities
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in summary:
                summary[sev] += 1

        return jsonify({"findings": findings, "summary": summary, "total": len(findings)})

    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse AI response. Try again."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
