from flask import Flask, request, jsonify, send_from_directory
from openai import (
    OpenAI,
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    RateLimitError,
)
from dotenv import load_dotenv
import json
import os
import zipfile
import io
from graph_engine import (
    parse_tf_files,
    extract_references,
    build_graph,
    detect_cross_resource_risks,
    graph_to_json,
)

load_dotenv()

app = Flask(__name__, static_folder="static")
client = None


def get_provider():
    # Supported values: openai, deepseek, mock
    return os.environ.get("AI_PROVIDER", "openai").strip().lower()


def get_model():
    provider = get_provider()
    default_model = "deepseek-chat" if provider == "deepseek" else "gpt-4o"
    if provider == "mock":
        default_model = "mock-local"
    return os.environ.get("AI_MODEL", os.environ.get("OPENAI_MODEL", default_model))

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

@app.route("/multi")
def multi():
    return send_from_directory("static", "multi.html")

@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "terraguard",
            "provider": get_provider(),
            "model": get_model(),
        }
    )

def get_ai_client():
    global client
    provider = get_provider()
    if provider == "mock":
        return "mock"

    if provider == "deepseek":
        api_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        if not api_key:
            return None
        if client is None:
            client = OpenAI(api_key=api_key, base_url=base_url)
        return client

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    if client is None:
        client = OpenAI(api_key=api_key)
    return client


def mock_findings(tf_code):
    findings = []
    issue_id = 1

    def add(severity, title, resource, line_hint, description, fix, cwe, tags):
        nonlocal issue_id
        findings.append(
            {
                "id": f"TG-{issue_id:03d}",
                "severity": severity,
                "title": title,
                "resource": resource,
                "line_hint": line_hint,
                "description": description,
                "fix": fix,
                "cwe": cwe,
                "tags": tags,
            }
        )
        issue_id += 1

    lower_tf = tf_code.lower()
    if "0.0.0.0/0" in lower_tf and ("from_port   = 22" in lower_tf or "from_port = 22" in lower_tf):
        add(
            "HIGH",
            "SSH open to the internet",
            "aws_security_group.*",
            "ingress block for port 22",
            "Inbound SSH access from 0.0.0.0/0 increases brute-force and lateral movement risk.",
            'Restrict ingress CIDR to trusted admin IPs or use SSM Session Manager; avoid public SSH where possible.',
            "CWE-284",
            ["network", "security-group", "ingress"],
        )

    if "public-read" in lower_tf or "publicly_accessible = true" in lower_tf:
        add(
            "HIGH",
            "Public resource exposure detected",
            "aws_s3_bucket.* / aws_db_instance.*",
            "public ACL or publicly_accessible setting",
            "Public access on storage/database resources can expose sensitive data.",
            "Disable public access, enforce private ACLs, and enable explicit access policies.",
            "CWE-200",
            ["public-access", "data-exposure"],
        )

    if "password" in lower_tf and '"' in tf_code:
        add(
            "MEDIUM",
            "Hardcoded credential in Terraform",
            "resource block with password field",
            "password assignment line",
            "Hardcoded secrets in IaC can leak via Git history and logs.",
            "Move credentials to a secrets manager (AWS Secrets Manager/Vault) and reference them securely.",
            "CWE-798",
            ["secrets", "credentials", "terraform"],
        )

    if "encrypted = false" in lower_tf or "storage_encrypted = false" in lower_tf:
        add(
            "MEDIUM",
            "Encryption disabled",
            "storage/database resource",
            "encryption configuration line",
            "Disabling encryption at rest increases the impact of data exfiltration and snapshot leakage.",
            "Set encryption fields to true and enforce KMS keys for managed resources.",
            "CWE-311",
            ["encryption", "data-protection"],
        )

    return findings


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    tf_code = data.get("code", "").strip()

    if not tf_code:
        return jsonify({"error": "No Terraform code provided"}), 400

    if len(tf_code) > 50000:
        return jsonify({"error": "File too large (max 50KB)"}), 400

    provider = get_provider()
    ai_client = get_ai_client()
    if ai_client is None:
        return jsonify({"error": "API key is missing. Set it in .env and try again."}), 503

    if provider == "mock":
        findings = mock_findings(tf_code)
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in summary:
                summary[sev] += 1
        return jsonify({"findings": findings, "summary": summary, "total": len(findings)})

    try:
        response = ai_client.chat.completions.create(
            model=get_model(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this Terraform code for security issues:\n\n```hcl\n{tf_code}\n```"}
            ],
            temperature=0.1,
            max_tokens=4000
        )

        raw = (response.choices[0].message.content or "").strip()
        if not raw:
            return jsonify({"error": "Empty AI response received."}), 502

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
    except AuthenticationError:
        return jsonify({"error": "Invalid API key for the configured provider."}), 401
    except RateLimitError:
        return jsonify({"error": "Rate limit reached. Please retry shortly."}), 429
    except APIConnectionError:
        return jsonify({"error": "Unable to reach provider API. Check network connectivity."}), 503
    except APIStatusError as e:
        return jsonify({"error": f"Provider API error: {e.status_code}"}), 502
    except Exception as e:
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500

@app.route("/analyze/multi", methods=["POST"])
def analyze_multi():
    """Multi-file Terraform analysis with dependency graph.
    Accepts either:
    - JSON: {"files": {"main.tf": "...", "vpc.tf": "..."}}
    - or file upload (multipart/form-data with .tf files or .zip)
    """
    files = {}

    # Handle JSON input
    if request.is_json:
        data = request.get_json(silent=True) or {}
        files = data.get("files", {})
        if not files or not isinstance(files, dict):
            return jsonify({"error": "Expected {\"files\": {\"name.tf\": \"content\"}}"}), 400

    # Handle file upload
    elif request.files:
        uploaded = request.files.getlist("files")
        for f in uploaded:
            if f.filename.endswith(".tf") or f.filename.endswith(".tfvars"):
                files[f.filename] = f.read().decode("utf-8", errors="ignore")
            elif f.filename.endswith(".zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
                        for name in zf.namelist():
                            if name.endswith(".tf") or name.endswith(".tfvars"):
                                files[name] = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    pass

    if not files:
        return jsonify({"error": "No valid .tf files provided"}), 400

    # Parse HCL and build graph
    try:
        resources, raw_blocks = parse_tf_files(files)
        edges = extract_references(raw_blocks, resources)
        G = build_graph(resources, edges)
    except Exception as e:
        return jsonify({"error": f"Failed to parse Terraform files: {str(e)}"}), 400

    # Detect cross-resource risks
    graph_findings = detect_cross_resource_risks(G, resources)

    # Also run LLM analysis on each file if provider is configured
    llm_findings = []
    provider = get_provider()
    if provider != "mock":
        ai_client = get_ai_client()
        if ai_client:
            for fname, content in files.items():
                if len(content.strip()) < 20:
                    continue
                try:
                    response = ai_client.chat.completions.create(
                        model=get_model(),
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": f"Analyze {fname}:\n\n```hcl\n{content[:10000]}\n```"}
                        ],
                        temperature=0.1,
                        max_tokens=3000
                    )
                    raw = (response.choices[0].message.content or "").strip()
                    if raw.startswith("```"):
                        raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
                    file_findings = json.loads(raw)
                    for f in file_findings:
                        f["file"] = fname
                        f["engine"] = "ai-semantic"
                    llm_findings.extend(file_findings)
                except Exception:
                    pass

    # Merge findings
    all_findings = graph_findings + llm_findings
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        if sev in summary:
            summary[sev] += 1

    # Serialize graph for visualization
    graph_json = graph_to_json(G, resources)

    return jsonify({
        "findings": all_findings,
        "summary": summary,
        "total": len(all_findings),
        "graph": graph_json,
        "files_analyzed": list(files.keys()),
        "resource_count": len(resources),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
