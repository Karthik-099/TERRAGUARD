# TerraGuard
### AI-Powered Terraform Security Agent

TerraGuard analyzes your Terraform/IaC code for security vulnerabilities, misconfigurations, and best practice violations using GPT-4o.

---

## Features
- Detects CRITICAL / HIGH / MEDIUM / LOW / INFO severity issues
- Catches public S3 buckets, open security groups, hardcoded secrets
- Flags overprivileged IAM roles, unencrypted storage, exposed ports
- Provides concrete fix suggestions for every finding
- Drag and drop `.tf` file upload
- Clean terminal-style UI

---

## Setup

### 1. Clone and install
```bash
git clone https://github.com/Karthik-099/TERRAGUARD.git
cd TERRAGUARD
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set your OpenAI API key
```bash
export OPENAI_API_KEY=your_key_here
```

### 3. Run
```bash
python app.py
```

### 4. Open browser
```
http://localhost:5000
```

---

## What it detects
| Category | Examples |
|---|---|
| IAM | Wildcard actions (`*`), overprivileged roles |
| Network | SSH/RDP/DB ports open to `0.0.0.0/0` |
| Storage | Public S3 buckets, unencrypted EBS/RDS |
| Secrets | Hardcoded passwords, API keys in `.tf` files |
| Logging | Missing CloudTrail, VPC flow logs disabled |
| Encryption | Unencrypted volumes, insecure TLS |

---

## Tech Stack
- Backend: Python + Flask
- AI: OpenAI GPT-4o
- Frontend: Vanilla HTML/CSS/JS (zero dependencies)

---

## Built by
Karthik - DevOps / Platform Engineer
[Portfolio](https://karthik-portfolioo.netlify.app)
