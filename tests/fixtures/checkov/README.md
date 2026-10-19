# Checkov fixtures

`insecure.json` and `secure.json` are real Checkov 3.3.29 JSON outputs for `terraform-lab/insecure`
and `terraform-lab/secure`, captured with:

```bash
checkov --directory terraform-lab/<name> --framework terraform --output json --soft-fail --skip-download
```

The only edit is path sanitization: the local absolute path of each lab folder was replaced with
`/lab/<name>`. Regenerate them after changing the lab files or upgrading Checkov.

`fake_checkov.py` replays these files so unit tests run without Checkov installed. The real
scanner is exercised by `test_real_checkov_lab_demo`, which is skipped when Checkov is not available.
