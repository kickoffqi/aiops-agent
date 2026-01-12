# AIOps Remediation PR

## 1. Incident Summary
- **Incident ID**: {{incident.id}}
- **Service / App**: {{incident.service}}
- **Namespace / Cluster**: {{incident.namespace}} / {{incident.cluster}}
- **First Seen (UTC)**: {{incident.first_seen}}
- **Severity**: {{incident.severity}}
- **Triage Class**: {{triage.class}} (confidence={{triage.confidence}}, dominance_ratio={{triage.dominance_ratio}})

## 2. Evidence (Why this change)
### Metrics
- CrashLoopBackOff / Restarts: {{evidence.metrics.restarts_summary}}
- Probes: {{evidence.metrics.probes_summary}}
- Resource / HPA: {{evidence.metrics.resources_summary}}

### Logs (Loki excerpts / patterns)
- Top patterns: {{evidence.logs.top_patterns}}
- Example log lines:
  - {{evidence.logs.example_1}}
  - {{evidence.logs.example_2}}

> Evidence source: `aiops/reports/{{incident.report_file}}`

## 3. Proposed Remediation
### Change Type
- [ ] config
- [ ] dependency
- [ ] crashloop
- [ ] probes
- [ ] scaling
- [ ] rollback / restart
- [ ] unknown / investigation

### What is changing
- Files changed:
  - {{change.files}}
- Patch/Overlay:
  - {{change.patch_path}}

### Risk Level
- **Risk**: {{risk.level}}  (auto/manual)
- **Reason**: {{risk.reason}}
- **Guardrails**:
  - Max replicas: {{guardrails.max_replicas}}
  - Allowed actions: {{guardrails.allowed_actions}}
  - Protected areas: {{guardrails.protected_areas}}

## 4. Validation Plan (Post-check)
Runbook:
1) Confirm rollout status:
   - `kubectl -n {{incident.namespace}} rollout status deploy/{{incident.service}}`
2) Confirm metrics recovery:
   - Restarts stable / decreasing for {{validation.window_minutes}} minutes
   - Probe success ratio > {{validation.probe_threshold}}
3) Confirm logs:
   - Error pattern "{{validation.log_pattern}}" not observed for {{validation.window_minutes}} minutes

## 5. Rollback Plan
- **Fast rollback**: Revert this PR (preferred)
- **Emergency rollback**:
  - `argocd app rollback {{argo.app_name}} --revision <previous>`
- **Verification after rollback**:
  - Same checks as Validation Plan

## 6. Approvals / Gating
- Required approvals: {{approvals.required}}
- CODEOWNERS path: {{approvals.codeowners}}
- Auto-merge eligible: {{approvals.auto_merge_eligible}}
- Notes:
  - {{approvals.notes}}

---
### Bot Output (for audit)
- Remediation Plan ID: {{bot.plan_id}}
- Bot Version: {{bot.version}}
- Generated At: {{bot.generated_at}}