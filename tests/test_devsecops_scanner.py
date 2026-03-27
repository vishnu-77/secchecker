import pytest
from secchecker.devsecops_patterns import DEVSECOPS_PATTERNS, DEVSECOPS_SEVERITY_MAP
from secchecker.devsecops_scanner import scan_file_devsecops, scan_directory_devsecops


def test_devsecops_patterns_exist():
    assert isinstance(DEVSECOPS_PATTERNS, dict)
    assert len(DEVSECOPS_PATTERNS) >= 20


def test_dockerfile_from_latest(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM ubuntu:latest\nRUN echo hello\n")
    findings = scan_file_devsecops(str(f))
    assert "Dockerfile - FROM latest tag" in findings


def test_dockerfile_secret_in_env(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM ubuntu:20.04\nENV PASSWORD=supersecret123\n")
    findings = scan_file_devsecops(str(f))
    assert "Dockerfile - Secret in ENV" in findings


def test_dockerfile_curl_pipe_to_shell(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM ubuntu:20.04\nRUN curl https://example.com/script.sh | bash\n")
    findings = scan_file_devsecops(str(f))
    assert "Dockerfile - curl pipe to shell" in findings


def test_k8s_privileged_container(tmp_path):
    f = tmp_path / "deployment.yaml"
    f.write_text("spec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n")
    findings = scan_file_devsecops(str(f))
    assert "K8s - Privileged container" in findings


def test_terraform_public_s3(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    findings = scan_file_devsecops(str(f))
    assert "Terraform - S3 bucket public ACL" in findings


def test_terraform_open_security_group(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text('resource "aws_security_group_rule" "r" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
    findings = scan_file_devsecops(str(f))
    assert "Terraform - Open security group ingress" in findings


def test_file_type_filter_terraform_not_on_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text('cidr_blocks = ["0.0.0.0/0"]\n')
    findings = scan_file_devsecops(str(f))
    assert "Terraform - Open security group ingress" not in findings


def test_scan_directory_devsecops(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:latest\n")
    results = scan_directory_devsecops(str(tmp_path))
    assert len(results) >= 1


def test_scan_nonexistent_file():
    assert scan_file_devsecops("nonexistent_file.yaml") == {}


def test_scan_nonexistent_directory():
    with pytest.raises(FileNotFoundError):
        scan_directory_devsecops("nonexistent_dir_xyz")


def test_severity_map_coverage():
    for key in DEVSECOPS_SEVERITY_MAP.values():
        assert key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
