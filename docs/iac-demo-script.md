# Seven-minute demo: Infrastructure-as-Code security scanning

Goal: show a real scanner finding real misconfigurations in Terraform, the fixes, and a rescan that
proves which checks changed. No cloud account, no credentials, nothing deployed.

**Before the interview (2 minutes, not on the clock)**

```bash
agentshield iac scanner
```

```bash
agentshield serve
```

Open http://127.0.0.1:8000/iac and a terminal side by side. Keep `terraform-lab/insecure/main.tf`
and `terraform-lab/secure/main.tf` open in an editor. Don't pre-run the demo; the scan is fast
(about 10 seconds for both folders).

---

## 0:00 – 0:45 · Framing

"This is Infrastructure-as-Code security scanning, which is different from AgentShield's live cloud
posture scanner. It reads Terraform files with Checkov, the open-source scanner. Nothing is deployed
and no cloud credentials are involved. The same idea shifts security left: catch the
misconfiguration in the pull request, before it exists in an account."

Point at the scanner banner: Checkov version, offline mode.

## 0:45 – 2:00 · The insecure Terraform

Show `terraform-lab/insecure/main.tf` and name the three problem areas:

1. **Public storage**: Block Public Access turned off and a bucket policy with `Principal = "*"`.
2. **Open network**: SSH (22) and RDP (3389) from `0.0.0.0/0`, all egress allowed.
3. **Broad IAM**: a policy allowing `Action = "*"` on `Resource = "*"`.

"These are among the most common real cloud breach paths: public data, exposed admin ports, and
admin-equivalent roles."

## 2:00 – 3:30 · Scan and findings

Click **Run lab demo (scan, fix, rescan)** (or run `agentshield iac demo` in the terminal).

In **Findings**, choose the insecure scan, status `failed`:

- 25 failed checks across 7 resources, with exact file and line ranges.
- Filter **Resource** to `aws_security_group.app`: CKV_AWS_24 (SSH), CKV_AWS_25 (RDP), CKV_AWS_382
  (egress).
- Expand CKV_AWS_24: the code excerpt Checkov evaluated, the evaluated keys, the remediation.
- Point at **Severity: not provided**. "Checkov's open-source checks don't assign severity; that comes
  from the commercial platform. I chose not to invent one. Prioritization here comes from what the
  check protects, which I explain rather than fake with a number."

## 3:30 – 5:00 · The fixes

Show `terraform-lab/secure/main.tf`, same resource names:

- Block Public Access all `true`; the bucket policy now only *denies* non-TLS access; KMS
  encryption with key rotation and an explicit key policy; versioning; lifecycle rule.
- Security group: HTTPS from an internal CIDR only; egress limited to HTTPS.
- IAM: `s3:GetObject` and `s3:ListBucket` on the one bucket.

"Same resource addresses, so the rescan can be compared check by check."

## 5:00 – 6:15 · Rescan and comparison

Scroll to **Before and after**:

- 25 failed → 4 failed. **21 fixed, 0 new failures.**
- The comparison matches on `(check_id, resource address)`: "fixed" means the same check on the same
  resource went from FAILED to PASSED in a real rescan, not that a finding disappeared.
- **Still failing (4)**: access logging, cross-region replication, event notifications, and the
  security group not being attached to anything. "I left these on purpose. Each needs extra
  infrastructure (a log bucket, a second region, a queue, an instance), and the lab is about the
  three risk areas. The tool reports them honestly instead of me hiding them."

## 6:15 – 7:00 · Close

- Export the findings as CSV or JSON.
- "This sits next to the live AWS scanner and the agent red-team engine. The data model keeps IaC
  scans separate from live-account findings, so an IaC result is never presented as a live
  exposure. The connector design leaves room for AWS and GCP collectors on the live side."
- Tests: the parser runs against real captured Checkov output; one integration test runs Checkov
  for real in CI.

---

**Likely questions**

- *Why not trust Checkov's pass count as "secure"?* Static checks only see what is in the files;
  module inputs, account-level settings and runtime drift need the live scanner.
- *What would you add next?* Pull-request integration (scan only changed files), suppression with
  required justification, and mapping checks to the live-scanner rules so a file finding links to
  the deployed resource.
