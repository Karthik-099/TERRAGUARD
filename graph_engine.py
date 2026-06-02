import re
import json
import hcl2
import networkx as nx
from io import StringIO

# ── HCL parser ──────────────────────────────────────────────────────────────

def parse_tf_files(files: dict[str, str]) -> dict:
    """Parse multiple .tf file contents into a unified resource map.
    files: { filename: content }
    Returns: { "resource_type.resource_name": { ...attrs } }
    """
    resources = {}
    raw_blocks = {}  # store raw text blocks for reference extraction

    for filename, content in files.items():
        try:
            parsed = hcl2.load(StringIO(content))
        except Exception:
            continue

        for block_type, block_list in parsed.items():
            if not isinstance(block_list, list):
                continue
            for block in block_list:
                if not isinstance(block, dict):
                    continue
                if block_type == "resource":
                    for rtype, rinstances in block.items():
                        for rname, attrs in rinstances.items():
                            key = f"{rtype}.{rname}"
                            resources[key] = {
                                "type": rtype,
                                "name": rname,
                                "attrs": attrs if isinstance(attrs, dict) else {},
                                "file": filename,
                            }
                elif block_type == "data":
                    for dtype, dinstances in block.items():
                        for dname, attrs in dinstances.items():
                            key = f"data.{dtype}.{dname}"
                            resources[key] = {
                                "type": f"data.{dtype}",
                                "name": dname,
                                "attrs": attrs if isinstance(attrs, dict) else {},
                                "file": filename,
                            }

        raw_blocks[filename] = content

    return resources, raw_blocks


# ── Reference extractor ──────────────────────────────────────────────────────

REF_PATTERN = re.compile(r'\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\.[a-z_]+\b')

def extract_references(raw_blocks: dict[str, str], resources: dict) -> list[tuple]:
    """Return list of (source_key, target_key) edges from resource references."""
    edges = []
    resource_keys = set(resources.keys())

    for content in raw_blocks.values():
        # find which resource block we are in
        current = None
        for line in content.splitlines():
            # detect resource block header
            m = re.match(r'\s*resource\s+"([^"]+)"\s+"([^"]+)"', line)
            if m:
                current = f"{m.group(1)}.{m.group(2)}"
                continue
            if current:
                for ref_match in REF_PATTERN.finditer(line):
                    ref = ref_match.group(1)
                    if ref in resource_keys and ref != current:
                        edges.append((current, ref))

    return list(set(edges))


# ── Graph builder ────────────────────────────────────────────────────────────

def build_graph(resources: dict, edges: list[tuple]) -> nx.DiGraph:
    G = nx.DiGraph()
    for key, meta in resources.items():
        G.add_node(key, **meta)
    for src, dst in edges:
        G.add_edge(src, dst)
    return G


# ── Cross-resource risk rules ────────────────────────────────────────────────

def _attrs_str(attrs: dict) -> str:
    return json.dumps(attrs).lower()


def detect_cross_resource_risks(G: nx.DiGraph, resources: dict) -> list[dict]:
    findings = []
    issue_id = [1]

    def add(severity, title, related, description, fix, cwe, tags):
        findings.append({
            "id": f"TG-GRAPH-{issue_id[0]:03d}",
            "severity": severity,
            "title": title,
            "resource": " + ".join(related),
            "line_hint": f"cross-resource pattern across: {', '.join(related)}",
            "description": description,
            "fix": fix,
            "cwe": cwe,
            "tags": tags,
            "related_resources": related,
            "engine": "dependency-graph",
        })
        issue_id[0] += 1

    lambdas   = {k: v for k, v in resources.items() if v["type"] == "aws_lambda_function"}
    iam_roles = {k: v for k, v in resources.items() if v["type"] == "aws_iam_role"}
    iam_pols  = {k: v for k, v in resources.items() if v["type"] in ("aws_iam_role_policy", "aws_iam_policy")}
    apigws    = {k: v for k, v in resources.items() if v["type"] in ("aws_api_gateway_rest_api", "aws_apigatewayv2_api")}
    buckets   = {k: v for k, v in resources.items() if v["type"] == "aws_s3_bucket"}
    sgs       = {k: v for k, v in resources.items() if v["type"] == "aws_security_group"}
    dbs       = {k: v for k, v in resources.items() if v["type"] == "aws_db_instance"}
    instances = {k: v for k, v in resources.items() if v["type"] == "aws_instance"}

    # Rule 1: Lambda + wildcard IAM policy + public API Gateway = privilege escalation path
    for lk, lv in lambdas.items():
        connected_roles = [n for n in nx.neighbors(G, lk) if n in iam_roles] if lk in G else []
        connected_roles += [n for n in G.predecessors(lk) if n in iam_roles] if lk in G else []
        for rk in connected_roles:
            connected_pols = [n for n in nx.neighbors(G, rk) if n in iam_pols] if rk in G else []
            connected_pols += [n for n in G.predecessors(rk) if n in iam_pols] if rk in G else []
            for pk in connected_pols:
                pol_str = _attrs_str(resources[pk]["attrs"])
                if '"*"' in pol_str or "\"action\": \"*\"" in pol_str or "action.*\\*" in pol_str:
                    # check if any API GW connects to the lambda
                    gw_neighbors = [n for n in G.predecessors(lk) if n in apigws] if lk in G else []
                    if gw_neighbors:
                        add(
                            "CRITICAL",
                            "Public API Gateway triggers Lambda with wildcard IAM policy",
                            [list(apigws.keys())[0], lk, rk, pk],
                            "A Lambda function is publicly reachable via API Gateway and executes with a wildcard IAM role policy. "
                            "This creates a privilege escalation path: an attacker who exploits the Lambda can perform any AWS action.",
                            "Scope the Lambda execution role to only the specific actions and resources it needs. "
                            "Remove Action:* and Resource:* from the IAM policy.",
                            "CWE-269",
                            ["lambda", "iam", "api-gateway", "privilege-escalation", "cross-resource"],
                        )
                    else:
                        add(
                            "HIGH",
                            "Lambda function has wildcard IAM execution role",
                            [lk, rk, pk],
                            "Lambda is attached to an IAM role with wildcard permissions (Action: * / Resource: *). "
                            "If the function is compromised, attackers gain full AWS account access.",
                            "Apply least-privilege: define exact Actions and specific Resource ARNs in the policy.",
                            "CWE-269",
                            ["lambda", "iam", "privilege-escalation"],
                        )

    # Rule 2: EC2 instance using an open security group + unencrypted EBS
    for ik, iv in instances.items():
        connected_sgs = [n for n in nx.neighbors(G, ik) if n in sgs] if ik in G else []
        connected_sgs += [n for n in G.predecessors(ik) if n in sgs] if ik in G else []
        open_sgs = []
        for sk in connected_sgs:
            sg_str = _attrs_str(resources[sk]["attrs"])
            if "0.0.0.0/0" in sg_str:
                open_sgs.append(sk)
        if open_sgs:
            inst_str = _attrs_str(iv["attrs"])
            if "encrypted\": false" in inst_str or "\"encrypted\":false" in inst_str:
                add(
                    "HIGH",
                    "EC2 instance with open security group and unencrypted root volume",
                    [ik] + open_sgs,
                    "An EC2 instance is associated with a security group open to 0.0.0.0/0 and has an unencrypted root EBS volume. "
                    "Exposure to the internet combined with unencrypted storage increases breach impact.",
                    "Restrict security group ingress to known CIDRs. Enable EBS encryption: set encrypted = true in root_block_device.",
                    "CWE-311",
                    ["ec2", "security-group", "encryption", "cross-resource"],
                )

    # Rule 3: Public S3 bucket + missing server-side encryption
    for bk, bv in buckets.items():
        b_str = _attrs_str(bv["attrs"])
        is_public = "public-read" in b_str or "public-read-write" in b_str
        missing_enc = "server_side_encryption_configuration" not in b_str
        if is_public and missing_enc:
            add(
                "CRITICAL",
                "Public S3 bucket with no server-side encryption",
                [bk],
                "S3 bucket is publicly readable and has no server-side encryption configured. "
                "Any data stored is both exposed to the internet and unencrypted at rest.",
                "Set ACL to private, enable Block Public Access, and add a server_side_encryption_configuration block with AES256 or aws:kms.",
                "CWE-311",
                ["s3", "encryption", "public-access", "cross-resource"],
            )

    # Rule 4: RDS instance publicly accessible + attached to open SG
    for dk, dv in dbs.items():
        d_str = _attrs_str(dv["attrs"])
        if "publicly_accessible\": true" in d_str or "\"publicly_accessible\":true" in d_str:
            connected_sgs = [n for n in nx.neighbors(G, dk) if n in sgs] if dk in G else []
            connected_sgs += [n for n in G.predecessors(dk) if n in sgs] if dk in G else []
            open_sgs = [sk for sk in connected_sgs if "0.0.0.0/0" in _attrs_str(resources[sk]["attrs"])]
            if open_sgs:
                add(
                    "CRITICAL",
                    "Publicly accessible RDS instance with open security group",
                    [dk] + open_sgs,
                    "RDS instance is set to publicly_accessible = true and is associated with a security group "
                    "open to 0.0.0.0/0. The database is directly reachable from the internet.",
                    "Set publicly_accessible = false. Restrict the security group to application-tier CIDRs only. "
                    "Place the RDS instance in a private subnet.",
                    "CWE-284",
                    ["rds", "security-group", "public-access", "cross-resource"],
                )

    return findings


# ── Graph serializer (for API response) ─────────────────────────────────────

def graph_to_json(G: nx.DiGraph, resources: dict) -> dict:
    nodes = []
    for n in G.nodes():
        meta = resources.get(n, {})
        nodes.append({
            "id": n,
            "type": meta.get("type", "unknown"),
            "file": meta.get("file", ""),
        })
    edges = [{"source": u, "target": v} for u, v in G.edges()]
    return {"nodes": nodes, "edges": edges}
