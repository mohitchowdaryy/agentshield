# Likely interview questions, with answers grounded in this codebase

**Why not use an LLM classifier to block prompt injection?**
Classifiers are probabilistic and can themselves be injected. The gateway
(`src/agentshield/agent/gateway.py`) decides from the policy file, validated arguments and run
context only. A classifier could be added as one more signal, never as the authority.

**How do you know the model "saw" the payload?**
The runtime records every string placed in the model's context (`RunTrace.model_inputs`, and the
exact request per turn in `model_interactions`). The evaluator checks for the payload, including
its JSON-escaped form, because tool output is serialized.

**What's the difference between a failed attack and a safe model?**
`defense_layer` separates them: `model` means no unsafe call was proposed; `gateway` means the model
was steered (a model-level weakness, reported) but enforcement held. Only an executed violation
counts as `succeeded`.

**Why does untrusted context matter to authorization?**
The runtime marks every call proposed after retrieved or tool output entered the context. The
protected policy requires human approval for `send_message` in that state (GW-007), which turns
"the model was influenced" into a deterministic control.

**How is path traversal handled twice?**
The gateway rejects `..`, absolute, backslash, percent-encoded and control-character paths
(GW-003). Independently, the tool layer works on an in-memory dict and normalizes paths without
ever escaping the root, so even the vulnerable policy cannot reach real files.

**How do you avoid duplicate findings?**
`sha256(rule_id | account | region | resource_arn)` as a unique fingerprint; each scan adds an
observation row. A gap-free re-scan that no longer sees a finding marks it resolved.

**What happens when the scanner lacks permissions?**
The call is recorded as a `CollectionGap`, the field stays `unknown`, and rules skip it. You see
partial results instead of a crash or a false "compliant".

**Why is a public bucket policy sometimes only "low"?**
If `RestrictPublicBuckets` is enabled at the bucket or account level, S3 limits a public policy to
AWS service principals and the owner account. The evidence records that mitigation.

**Is the correlation an attack path?**
No. It is a modeled path with evidence links. Its status says whether the agent-side step was
observed in a sandbox run. The tools never call AWS, so the cloud step is never exercised.

**How would you test a real model fairly?**
Same scenarios through `AnthropicProvider`, many trials per scenario, report counts and confidence
intervals, and keep refusal-fallback turns attributed to the model that served them (the runtime
emits `model_fallback` events).

**What would you build next?**
Repeated-trial statistics, more scenarios (multi-step manipulation, excessive agency), a PyRIT
adapter for payload converters, and effective-permission analysis with IAM Access Analyzer.
