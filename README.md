# AWS IAM Security Audit Tool

A Python-based security auditing tool that automatically detects IAM misconfigurations in AWS environments and provides actionable remediation guidance.

## What It Does

- Audits all IAM users for missing MFA and weak access key hygiene
- Detects overly permissive policies (AdministratorAccess)
- Checks account password policy against CIS AWS Foundations Benchmark
- Scans S3 buckets for public access misconfigurations
- Generates timestamped audit reports
- Bash remediation script to fix detected issues

## Tools & Technologies

- Python 3, Boto3, AWS CLI
- AWS IAM, S3, CloudTrail
- CIS AWS Foundations Benchmark
- Least-privilege IAM principles

## Project Structure

```
iam-security-audit/
├── scripts/
│   ├── iam_audit.py       # Main audit script
│   └── remediate.sh       # Remediation script
└── reports/               # Auto-generated audit reports
```

## Sample Output

```
==================================================
  AWS IAM SECURITY AUDIT
==================================================
=== PASSWORD POLICY AUDIT ===
  ⚠️  No password policy set! This is a security risk.

=== IAM USER AUDIT ===
Total users found: 1
[USER] iam-auditor
  ⚠️  NO MFA enabled for iam-auditor
  🔑 Access key AKIA... | Status: Active | Age: 0 days

=== S3 BUCKET AUDIT ===
Total buckets found: 0
✅ Audit complete!
```

## Security Concepts Demonstrated

- IAM least-privilege access design
- CIS Benchmark compliance checks
- Automated security auditing with Python (Boto3)
- Access key lifecycle management
- MFA enforcement detection
- S3 public access misconfiguration detection

## How to Run

```bash
# Install dependencies
pip3 install boto3

# Configure AWS CLI
aws configure --profile iam-auditor

# Run audit
python3 scripts/iam_audit.py

# Run remediation check
bash scripts/remediate.sh
```
