#!/bin/bash
# IAM Security Remediation Script
# Project: IAM Security Audit
# Author: Mohammed Ashik Nizamudeen

PROFILE="iam-auditor"

echo "========================================"
echo "  AWS IAM REMEDIATION SCRIPT"
echo "========================================"

# Fix 1: Set a strong password policy
echo ""
echo "[*] Setting strong IAM password policy..."
aws iam update-account-password-policy \
  --profile $PROFILE \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 12 \
  --allow-users-to-change-password

if [ $? -eq 0 ]; then
  echo "  ✅ Password policy updated successfully"
else
  echo "  ⚠️  Could not update password policy (insufficient permissions - expected for read-only auditor)"
fi

# Fix 2: List users without MFA
echo ""
echo "[*] Checking for users without MFA..."
aws iam list-users --profile $PROFILE \
  --query 'Users[*].UserName' \
  --output text | tr '\t' '\n' | while read username; do
    mfa_count=$(aws iam list-mfa-devices \
      --profile $PROFILE \
      --user-name "$username" \
      --query 'length(MFADevices)' \
      --output text)
    if [ "$mfa_count" -eq 0 ]; then
      echo "  ⚠️  $username has no MFA - ACTION REQUIRED: Assign MFA device manually in console"
    else
      echo "  ✅ $username has MFA enabled"
    fi
done

# Fix 3: Find inactive access keys
echo ""
echo "[*] Checking for inactive access keys..."
aws iam list-users --profile $PROFILE \
  --query 'Users[*].UserName' \
  --output text | tr '\t' '\n' | while read username; do
    aws iam list-access-keys \
      --profile $PROFILE \
      --user-name "$username" \
      --query 'AccessKeyMetadata[?Status==`Inactive`].[UserName,AccessKeyId]' \
      --output text | while read line; do
        if [ ! -z "$line" ]; then
          echo "  ⚠️  Inactive key found: $line - should be deleted"
        fi
      done
done

echo ""
echo "========================================"
echo "  Remediation check complete!"
echo "  Note: Some fixes require root/admin"
echo "  privileges and must be done manually."
echo "========================================"