"""
cee_scanner.skills.iac
======================
IaC (Infrastructure as Code) Security Check

Detects publicly exposed infrastructure configuration files that leak
cloud credentials, internal topology, secrets, or deployment details.

Checks:
  - Terraform state files (.tfstate) — contain all resource secrets
  - Terraform plan/config files (.tf)
  - CloudFormation templates
  - Kubernetes configs and secrets
  - Ansible playbooks and vault files
  - Helm chart values
  - Pulumi state
  - CI/CD pipeline configs with cloud credentials
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.iac")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}


# (path, label, severity, confirm_pattern)
IAC_PROBES = [
    # ── Terraform ─────────────────────────────────────────────────────────────
    ("/terraform.tfstate",
     "Terraform state file exposed",
     "critical",
     r'"terraform_version"|"resources"'),

    ("/terraform.tfstate.backup",
     "Terraform state backup exposed",
     "critical",
     r'"terraform_version"|"resources"'),

    ("/.terraform/terraform.tfstate",
     "Terraform state (hidden dir) exposed",
     "critical",
     r'"terraform_version"'),

    ("/main.tf",
     "Terraform config exposed",
     "warning",
     r'resource\s+"|provider\s+"'),

    ("/variables.tf",
     "Terraform variables exposed",
     "warning",
     r'variable\s+"'),

    ("/outputs.tf",
     "Terraform outputs exposed",
     "warning",
     r'output\s+"'),

    # ── CloudFormation ────────────────────────────────────────────────────────
    ("/cloudformation.json",
     "CloudFormation template exposed",
     "critical",
     r'"AWSTemplateFormatVersion"|"Resources"'),

    ("/cloudformation.yaml",
     "CloudFormation template exposed",
     "critical",
     r'AWSTemplateFormatVersion:|Resources:'),

    ("/template.yaml",
     "SAM/CloudFormation template exposed",
     "warning",
     r'AWSTemplateFormatVersion:|Transform:'),

    ("/template.json",
     "CloudFormation template exposed",
     "warning",
     r'"AWSTemplateFormatVersion"'),

    # ── Kubernetes ────────────────────────────────────────────────────────────
    ("/kubernetes.yaml",
     "Kubernetes config exposed",
     "critical",
     r'apiVersion:|kind:'),

    ("/kubernetes.yml",
     "Kubernetes config exposed",
     "critical",
     r'apiVersion:|kind:'),

    ("/k8s.yaml",
     "Kubernetes config exposed",
     "critical",
     r'apiVersion:|kind:'),

    ("/deployment.yaml",
     "Kubernetes deployment exposed",
     "warning",
     r'apiVersion:|kind:\s*Deployment'),

    ("/secrets.yaml",
     "Kubernetes secrets file exposed",
     "critical",
     r'apiVersion:|kind:\s*Secret'),

    ("/.kube/config",
     "Kubeconfig exposed (cluster credentials)",
     "critical",
     r'apiVersion:|clusters:|users:'),

    # ── Ansible ───────────────────────────────────────────────────────────────
    ("/playbook.yml",
     "Ansible playbook exposed",
     "warning",
     r'hosts:|tasks:'),

    ("/ansible.cfg",
     "Ansible config exposed",
     "warning",
     r'\[defaults\]|inventory'),

    ("/inventory",
     "Ansible inventory exposed",
     "warning",
     r'\[.*\]|\d+\.\d+\.\d+\.\d+'),

    ("/vault.yml",
     "Ansible vault file exposed",
     "critical",
     r'\$ANSIBLE_VAULT|vault'),

    # ── Helm ─────────────────────────────────────────────────────────────────
    ("/values.yaml",
     "Helm values file exposed",
     "warning",
     r'image:|service:|ingress:'),

    ("/Chart.yaml",
     "Helm Chart.yaml exposed",
     "warning",
     r'apiVersion:|name:|version:'),

    # ── Pulumi ────────────────────────────────────────────────────────────────
    ("/Pulumi.yaml",
     "Pulumi config exposed",
     "warning",
     r'name:|runtime:|description:'),

    ("/Pulumi.dev.yaml",
     "Pulumi stack config exposed",
     "warning",
     r'config:'),

    # ── CI/CD with potential cloud creds ─────────────────────────────────────
    ("/.github/workflows/deploy.yml",
     "GitHub Actions deploy workflow exposed",
     "warning",
     r'uses:|steps:|AWS_|AZURE_|GCP_'),

    ("/.gitlab-ci.yml",
     "GitLab CI config exposed",
     "warning",
     r'stages:|script:'),

    ("/Jenkinsfile",
     "Jenkinsfile exposed",
     "warning",
     r'pipeline|agent|stages'),

    ("/buildspec.yml",
     "AWS CodeBuild spec exposed",
     "warning",
     r'version:|phases:'),

    ("/appspec.yml",
     "AWS CodeDeploy spec exposed",
     "warning",
     r'version:|os:'),

    # ── Secrets / credential patterns in misc files ───────────────────────────
    ("/config.yaml",
     "Config file exposed",
     "warning",
     r'(password|secret|key|token)\s*:'),

    ("/config.yml",
     "Config file exposed",
     "warning",
     r'(password|secret|key|token)\s*:'),

    ("/secrets.json",
     "Secrets JSON exposed",
     "critical",
     r'(password|secret|key|token)'),
]

# Patterns that indicate live credentials in Terraform state
TFSTATE_SECRET_PATTERNS = [
    r'"password"\s*:\s*"[^"]+"',
    r'"secret_key"\s*:\s*"[^"]+"',
    r'"access_key"\s*:\s*"[^"]+"',
    r'"private_key"\s*:\s*"-----BEGIN',
    r'"connection_string"\s*:\s*"[^"]+"',
]


def check_iac(domain: str) -> "CheckResult":
    """
    IaC Security — detect exposed infrastructure configuration files.

    Returns CRITICAL if Terraform state, K8s secrets, or cloud templates found.
    WARNING for CI/CD configs, Helm values, or Ansible playbooks.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("iac", domain)

    critical_findings = []
    warning_findings  = []
    credentials_found = []

    for path, label, severity, confirm_pat in IAC_PROBES:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=False, verify=False,
            )
            if r.status_code != 200:
                continue

            body = r.text[:8000]

            # Skip HTML responses
            if "<html" in body.lower()[:300] and "<!doctype" in body.lower()[:300]:
                continue

            # Validate with confirm pattern
            if confirm_pat and not re.search(confirm_pat, body, re.IGNORECASE):
                continue

            logger.info(f"IaC: {label} at {url}")

            # Extra check: does a Terraform state contain live credentials?
            if "tfstate" in path:
                for cred_pat in TFSTATE_SECRET_PATTERNS:
                    if re.search(cred_pat, body, re.IGNORECASE):
                        credentials_found.append(f"Live credentials in {path}")
                        break

            if severity == "critical" or path in [p for p, *_ in IAC_PROBES if _[1] == "critical"]:
                critical_findings.append(f"{label} ({path})")
            else:
                warning_findings.append(f"{label} ({path})")

        except Exception:
            continue

    all_findings = critical_findings + warning_findings

    if not all_findings:
        return result.ok(
            "IaC: no infrastructure config files exposed",
            "No Terraform, Kubernetes, CloudFormation, or Ansible files found publicly"
        )

    detail = ""
    if credentials_found:
        detail += "LIVE CREDENTIALS DETECTED:\n" + "\n".join(f"  !! {c}" for c in credentials_found) + "\n\n"
    if critical_findings:
        detail += "Critical:\n" + "\n".join(f"  • {f}" for f in critical_findings) + "\n"
    if warning_findings:
        detail += "Warnings:\n" + "\n".join(f"  • {f}" for f in warning_findings)

    if credentials_found or critical_findings:
        top = (credentials_found or critical_findings)[0]
        return result.critical(
            f"IaC: {len(critical_findings)} critical config(s) exposed — {top}",
            detail.strip(),
            impact=40,
        )
    else:
        return result.warn(
            f"IaC: {len(warning_findings)} config file(s) exposed — {warning_findings[0]}",
            detail.strip(),
            impact=15,
        )
