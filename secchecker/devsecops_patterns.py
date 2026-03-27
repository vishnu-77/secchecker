"""DevSecOps security patterns for Dockerfile, Kubernetes, Terraform, and CI/CD."""
from typing import Dict, List

DEVSECOPS_PATTERNS: Dict[str, str] = {
    # ---- Dockerfile ----
    "Dockerfile - FROM latest tag": r"(?m)^FROM\s+[^\s]+:latest\s*$",
    "Dockerfile - FROM without tag": r"(?m)^FROM\s+[a-zA-Z0-9/_.\-]+\s*$",
    "Dockerfile - Explicit root USER": r"(?m)^USER\s+root\s*$",
    "Dockerfile - ADD with remote URL": r"(?m)^ADD\s+https?://",
    "Dockerfile - Secret in ENV": r"(?mi)^ENV\s+.*(password|secret|key|token|api_key|private_key)\s*[=\s]+\S+",
    "Dockerfile - RUN with privileged flag": r"(?i)--privileged",
    "Dockerfile - COPY entire context": r"(?m)^COPY\s+\.\s+\.",
    "Dockerfile - curl pipe to shell": r"(?i)(curl|wget).*\|\s*(bash|sh|zsh|python)",

    # ---- Kubernetes YAML ----
    "K8s - Privileged container": r"(?i)privileged:\s*true",
    "K8s - allowPrivilegeEscalation": r"(?i)allowPrivilegeEscalation:\s*true",
    "K8s - runAsUser root": r"(?i)runAsUser:\s*0\b",
    "K8s - hostNetwork enabled": r"(?i)hostNetwork:\s*true",
    "K8s - hostPID enabled": r"(?i)hostPID:\s*true",
    "K8s - automountServiceAccountToken": r"(?i)automountServiceAccountToken:\s*true",
    "K8s - Plaintext secret in stringData": r"(?i)stringData:",

    # ---- Terraform ----
    "Terraform - Hardcoded AWS access key": r'(?i)(access_key|aws_access_key_id)\s*=\s*["\']AKIA[0-9A-Z]{16}["\']',
    "Terraform - Hardcoded AWS secret key": r'(?i)(secret_key|aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']',
    "Terraform - S3 bucket public ACL": r'(?i)acl\s*=\s*["\']public-read["\']',
    "Terraform - Open security group ingress": r'(?i)cidr_blocks\s*=\s*\[?\s*["\']0\.0\.0\.0/0["\']',
    "Terraform - RDS publicly accessible": r"(?i)publicly_accessible\s*=\s*true",
    "Terraform - Hardcoded DB password": r'(?i)(password|db_password|master_password)\s*=\s*["\'][^$\{][^"\']{3,}["\']',

    # ---- CI/CD Pipelines ----
    "CI - Secret echoed to log": r"(?i)(echo|run:.*echo)\s+.*\$\{\{?\s*secrets\.",
    "CI - pull_request_target trigger": r"(?i)pull_request_target",
    "CI - Unpinned GitHub Action": r"uses:\s+[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+@(?!v?\d)[a-zA-Z]",
    "Docker Compose - Secret in environment": r"(?mi)-\s+\w*(password|secret|key|token)=\S+",
}

FILE_TYPE_FILTER: Dict[str, List[str]] = {
    "Dockerfile - FROM latest tag": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - FROM without tag": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - Explicit root USER": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - ADD with remote URL": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - Secret in ENV": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - RUN with privileged flag": ["Dockerfile", "*.dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "Dockerfile - COPY entire context": ["Dockerfile", "*.dockerfile"],
    "Dockerfile - curl pipe to shell": ["Dockerfile", "*.dockerfile", "*.sh"],
    "K8s - Privileged container": ["*.yaml", "*.yml"],
    "K8s - allowPrivilegeEscalation": ["*.yaml", "*.yml"],
    "K8s - runAsUser root": ["*.yaml", "*.yml"],
    "K8s - hostNetwork enabled": ["*.yaml", "*.yml"],
    "K8s - hostPID enabled": ["*.yaml", "*.yml"],
    "K8s - automountServiceAccountToken": ["*.yaml", "*.yml"],
    "K8s - Plaintext secret in stringData": ["*.yaml", "*.yml"],
    "Terraform - Hardcoded AWS access key": ["*.tf", "*.tfvars"],
    "Terraform - Hardcoded AWS secret key": ["*.tf", "*.tfvars"],
    "Terraform - S3 bucket public ACL": ["*.tf", "*.tfvars"],
    "Terraform - Open security group ingress": ["*.tf", "*.tfvars"],
    "Terraform - RDS publicly accessible": ["*.tf", "*.tfvars"],
    "Terraform - Hardcoded DB password": ["*.tf", "*.tfvars"],
    "CI - Secret echoed to log": ["*.yml", "*.yaml"],
    "CI - pull_request_target trigger": ["*.yml", "*.yaml"],
    "CI - Unpinned GitHub Action": ["*.yml", "*.yaml"],
    "Docker Compose - Secret in environment": ["docker-compose.yml", "docker-compose.yaml", "*.yml", "*.yaml"],
}

DEVSECOPS_SEVERITY_MAP: Dict[str, str] = {
    "Dockerfile - Secret in ENV": "CRITICAL",
    "Terraform - Hardcoded AWS access key": "CRITICAL",
    "Terraform - Hardcoded AWS secret key": "CRITICAL",
    "Terraform - Hardcoded DB password": "CRITICAL",
    "K8s - Privileged container": "CRITICAL",
    "K8s - Plaintext secret in stringData": "CRITICAL",
    "Dockerfile - curl pipe to shell": "HIGH",
    "Dockerfile - RUN with privileged flag": "HIGH",
    "Dockerfile - Explicit root USER": "HIGH",
    "K8s - allowPrivilegeEscalation": "HIGH",
    "K8s - runAsUser root": "HIGH",
    "K8s - hostNetwork enabled": "HIGH",
    "K8s - hostPID enabled": "HIGH",
    "CI - Secret echoed to log": "HIGH",
    "CI - pull_request_target trigger": "HIGH",
    "Terraform - S3 bucket public ACL": "HIGH",
    "Terraform - Open security group ingress": "HIGH",
    "Terraform - RDS publicly accessible": "HIGH",
    "Docker Compose - Secret in environment": "HIGH",
    "Dockerfile - FROM latest tag": "MEDIUM",
    "Dockerfile - FROM without tag": "MEDIUM",
    "Dockerfile - ADD with remote URL": "MEDIUM",
    "Dockerfile - COPY entire context": "MEDIUM",
    "K8s - automountServiceAccountToken": "MEDIUM",
    "CI - Unpinned GitHub Action": "MEDIUM",
}
