import boto3
import json
from datetime import datetime, timezone

PROFILE = "iam-auditor"
REPORT = []

def log(msg):
    print(msg)
    REPORT.append(msg)

def check_users(iam):
    log("\n=== IAM USER AUDIT ===")
    users = iam.list_users()["Users"]
    log(f"Total users found: {len(users)}")

    for user in users:
        name = user["UserName"]
        log(f"\n[USER] {name}")

        # Check MFA
        mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
        if not mfa:
            log(f"  ⚠️  NO MFA enabled for {name}")
        else:
            log(f"  ✅ MFA enabled")

        # Check access keys
        keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        for key in keys:
            key_id = key["AccessKeyId"]
            status = key["Status"]
            created = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - created).days
            log(f"  🔑 Access key {key_id} | Status: {status} | Age: {age_days} days")
            if age_days > 90:
                log(f"  ⚠️  Key is older than 90 days - should be rotated!")
            if status == "Inactive":
                log(f"  ⚠️  Inactive key exists - should be deleted!")

        # Check attached policies
        policies = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        for p in policies:
            log(f"  📋 Policy: {p['PolicyName']}")
            if p["PolicyName"] == "AdministratorAccess":
                log(f"  🚨 CRITICAL: {name} has AdministratorAccess!")

def check_roles(iam):
    log("\n=== IAM ROLE AUDIT ===")
    roles = iam.list_roles()["Roles"]
    log(f"Total roles found: {len(roles)}")

    for role in roles:
        name = role["RoleName"]
        policies = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        for p in policies:
            if p["PolicyName"] == "AdministratorAccess":
                log(f"  🚨 CRITICAL: Role '{name}' has AdministratorAccess!")

def check_s3(session):
    log("\n=== S3 BUCKET AUDIT ===")
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        log(f"Total buckets found: {len(buckets)}")

        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        log(f"  🚨 CRITICAL: Bucket '{name}' is PUBLICLY accessible!")
                    else:
                        log(f"  ✅ Bucket '{name}' is private")
            except Exception as e:
                log(f"  ℹ️  Could not check bucket '{name}': {str(e)}")
    except Exception as e:
        log(f"  ℹ️  S3 check skipped: {str(e)}")

def check_password_policy(iam):
    log("\n=== PASSWORD POLICY AUDIT ===")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_len = policy.get("MinimumPasswordLength", 0)
        requires_symbols = policy.get("RequireSymbols", False)
        requires_numbers = policy.get("RequireNumbers", False)
        max_age = policy.get("MaxPasswordAge", None)

        log(f"  Min password length: {min_len} {'✅' if min_len >= 14 else '⚠️  Should be 14+'}")
        log(f"  Requires symbols: {requires_symbols} {'✅' if requires_symbols else '⚠️'}")
        log(f"  Requires numbers: {requires_numbers} {'✅' if requires_numbers else '⚠️'}")
        log(f"  Max password age: {max_age} days {'✅' if max_age and max_age <= 90 else '⚠️  Should be 90 days or less'}")
    except iam.exceptions.NoSuchEntityException:
        log("  ⚠️  No password policy set! This is a security risk.")

def save_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/iam_audit_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(REPORT))
    log(f"\n📄 Report saved to {filename}")

def main():
    log("=" * 50)
    log("  AWS IAM SECURITY AUDIT")
    log(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 50)

    session = boto3.Session(profile_name=PROFILE)
    iam = session.client("iam")

    check_password_policy(iam)
    check_users(iam)
    check_roles(iam)
    check_s3(session)
    save_report()

    log("\n✅ Audit complete!")

if __name__ == "__main__":
    main()