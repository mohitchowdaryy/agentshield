# Terraform lab

Infrastructure-as-Code files for AgentShield's IaC security scanning demo.

| Folder | Contents |
|---|---|
| `insecure/` | Intentionally misconfigured resources: public S3 bucket policy with Block Public Access disabled, SSH/RDP open to `0.0.0.0/0`, unrestricted egress, and an IAM policy allowing `*` on `*`. |
| `secure/` | The same resource names, fixed: private encrypted versioned bucket, HTTPS from an internal CIDR only, least-privilege IAM policy. |

**These files are never deployed.** AgentShield does not run `terraform init`, `plan` or `apply`, and
no cloud credentials are needed. Checkov reads the HCL files statically.

Scan them:

```bash
agentshield iac demo
```

Measured with Checkov 3.3.29: `insecure/` has 25 failed and 15 passed checks across 7 resources;
`secure/` has 4 failed and 41 passed across 11 resources. 21 checks went from FAILED to PASSED and
none were newly introduced.

The 4 checks still failing on `secure/` are left on purpose, because each needs extra
infrastructure that is out of scope for this lab:

| Check | Why it still fails |
|---|---|
| CKV_AWS_18 | S3 access logging needs a separate log bucket (which then needs its own controls) |
| CKV_AWS_144 | Cross-region replication needs a second bucket in another region |
| CKV2_AWS_62 | Event notifications need an SNS topic, SQS queue or Lambda target |
| CKV2_AWS_5 | The security group is not attached to an instance or load balancer in this lab |
