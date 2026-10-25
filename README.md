# LOG(N) Pacific — Hunt 13 // Operation Overreach (GF-INC-2026-0806)

> Published after the hunt closed on 15 August 2026.

**Result: 🥇 1st place — 50/50 complete sweep, 43,279 pts (+1,870 over 2nd).**

Advanced post-compromise threat hunt for **Greenfield Logistics**, a hybrid Entra + on-prem AD estate. Detected and correlated in the cloud, the incident sat unworked in the queue — the job was to reconstruct what happened *after* the alert fired, and where it led beyond the cloud.

- **Case:** GF-INC-2026-0806
- **Window:** 5–6 August 2026
- **Telemetry:** two Microsoft Sentinel workspaces — `LAW-Cyber-Range` (cloud: Entra, M365, Graph, MDI/MDE) and `LAW-SilentCorridor` (on-prem `_CL` tables) — plus MDE Advanced Hunting
- **Surfaces:** Microsoft Defender XDR / Defender for Identity, KQL across both workspaces

## The kill chain

1. **Initial access — stolen session cookie.** Finance user `m.smith` taken over via a replayed session token from a Singapore IP (`159.26.115.80`). No password, no MFA prompt — Defender fired *"Possible use of a stolen session cookie"* (the one identity-product alert that named *how* the session was held, not where it came from).
2. **Cloud collection.** Mailbox triage → pivot to a SharePoint file (`Invoice_Reconciliation_Q3.xlsx`) → hidden mailbox forward set via **`Set-Mailbox`** (not an inbox rule) → soft-deleted the bounce notifications → auto-dismissed its own risk detections.
3. **Recon — AzureHound.** A 1,227-request/minute Microsoft Graph enumeration burst (client self-identified as `azurehound` in the UserAgent), blocked at Azure Resource Manager by conditional access (`AADSTS50076`). Stole KeePass vaults + a VPN credentials file.
4. **On-prem pivot.** VPN in as `m.smith` — the second factor (Google Authenticator TOTP) satisfied because the **TOTP seed had been exfiltrated from the stolen KeePass vault**. Internal port sweep of the DC (visible only in `NTANetAnalytics` NSG flow logs; the on-prem SIEM never saw it), then **SharpHound** (samr/lsarpc/srvsvc named-pipe burst).
5. **AI-agent compromise (the centrepiece).** A prompt-injection buried in a helpdesk ticket — tagged `[GF-SEC-REMEDIATION]`, referencing `GF-IR-4488` — tricked the `svc_helpbot` MCP agent (`greenfield-it-mcp`, tool `reset_account_password`, `password_source=caller_supplied`) into resetting `t.harris`. The gate accepted an authorisation marker that came from untrusted content. **No alert fired on any of it** — the richest evidence (`LLMAgentLogs_CL`) had zero detection coverage.
6. **ESC13 privilege escalation.** The `GF-PrivilegedAccessLogon` certificate template's issuance policy is linked (via `msDS-OIDToGroupLink`) to group `GF-PKI-Privileged-Access`, which holds write-member on `GF-Tier0-Automation`, which holds WriteDacl on the domain root. Certificate issued to `t.harris` with **his own** UPN as SAN (nothing forged — strong binding had nothing to catch); PKINIT logon put the OID-linked group in his token, and he added himself to Tier-0.
7. **DCSync & impact.** `DS-Replication-Get-Changes-All` (no host-memory touch) — every account's secrets in under five seconds. GPP `Groups.xml` cpassword recovered (MS14-025), employee PII (`employee_records.csv`) staged.

## Notable analytic moments

- **A grader bug, not a wording miss.** The hardest ADCS question ("The Binding Question") rejected the correct ESC13 answer for hours; it landed the instant the host widened the grader — the concept was right the whole time. Watching the platform notification feed for live grader/format fixes turned a 0-solve wall into a solve.
- **Coverage inversion.** The AI-agent tables held the best evidence in the whole hunt and the *least* detection coverage — the lesson to carry out. A single cross-source rule (`LLMAgentLogs_CL` × `SecurityEvent`, alerting when an agent-driven reset targets an account the requester doesn't own) would have caught it at 11:53:55.
- **Response, not detection, was the failure.** Every classic technique was detected and correlated. The incident was still a loss because the alert that fired was never worked — the cheapest fix is automated containment, not another detection.

## Stages

Triage · Initial Access · Collection · Persistence & Evasion · Escalation · Bridge · Enumeration · **AI Compromise** · Certificate & Privilege · Detection Latency · Collection & Impact · Synthesis · **Response (10 IR judgment challenges)**.

## Response / remediation highlights (Stage 12)

Revoke the session before resetting the password (a reset doesn't kill a stolen token) · don't block anonymised exit IPs · rotate `krbtgt` twice with a gap ≥ max TGT lifetime · revoking the cert is insufficient without fixing the ESC13 template · the mail persistence is a `Set-Mailbox` forward, not an inbox rule · re-enrolling TOTP is useless when the seed was stolen → move to FIDO2 · the golden ticket from DCSync survives account-disable / Tier-0 removal / cert revocation · prompt-injection can't be detected away — fix the agent's authorisation architecture · **the biggest lever is response process, not technology** · rotate top-of-trust-down so nothing is re-burned.

---
*LOG(N) Pacific Cyber Range · Microsoft Sentinel (2 workspaces) + Defender XDR + MDI · KQL / Advanced Hunting. Hybrid identity intrusion featuring AI-agent prompt injection and AD CS ESC13.*
