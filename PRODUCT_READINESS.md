# Web Security Workbench — Enterprise Product Readiness Plan

## Current product claim (safe to demonstrate)

"An Android-compatible prototype for controlled SQL injection training, evidence review, and AI-assisted remediation guidance. The active SQLi probes run only against an intentionally vulnerable localhost lab."

**Do not claim:** production-ready autonomous penetration testing, comprehensive SQLi detection on customer websites, enterprise data security, or proven accuracy against real applications. Those features are not present or independently validated.

## Build gates before a Fortinet or enterprise demonstration

1. **Differentiation:** Explain the customer problem and what is better than existing scanners, including whether AI improves triage accuracy, remediation clarity, or analyst time.
2. **Authorized client mode:** Verified control of targets, signed permission, per-project domain/path scope, redirect/DNS safety, hard request caps, rate limits, stop switch, and audit trail.
3. **SQLi validation:** Test a documented, non-destructive, bounded methodology against a diverse suite of intentionally vulnerable and fixed applications. Measure false positives, false negatives, latency, and rate limits.
4. **Privacy:** Use enterprise-appropriate AI processing; implement retention controls, redaction, encryption, authentication, tenant isolation, and documented incident response.
5. **Product hardening:** Threat model, dependency inventory, security tests, unit/integration CI, independent penetration test, secure update process, versioned release builds, and backup/recovery.
6. **Commercial basics:** Clarify IP ownership and open-source licenses; prepare a short demo, benchmark results, architecture diagram, roadmap, pricing hypothesis, and terms for a pilot.
7. **Pilot:** Start with a written-scope test environment and collect verified outcomes and feedback before claiming enterprise readiness.

## Suggested demonstration flow

- Show the vulnerable lab producing a positive SQLi indicator and explain why it is only an indicator.
- Switch the lab to fixed mode and demonstrate that the same bounded probes no longer produce the pattern.
- Ask Gemini to explain the difference and propose parameterized-query remediation.
- Export the synthetic report and show the human-review workflow.
- End with the roadmap for controlled client mode, accuracy benchmarks, and privacy/security controls.

## Fortinet-specific positioning

Fortinet already sells **FortiDAST**, a dynamic application security testing product with crawling, vulnerability scanning, remediation guidance, and CI/CD integration. It also offers AI-assisted security workflows elsewhere in its portfolio. Therefore, "another AI vulnerability scanner" is not a differentiated acquisition thesis. A more credible angle to test is **self-service SQLi remediation with evidence-linked explanations and before/after fix verification for small teams**, or an integration/prototype for a specific workflow FortiDAST does not already address. Validate that gap with Fortinet technical stakeholders; do not assume it exists.

## Go-to-market caution

Knowing a sales leader may help secure feedback or an introduction, but it does not establish buyer interest, procurement authority, a valuation, or product fit. Consider a technical discovery meeting and scoped proof of concept first. Avoid using the Fortinet name or branding in the product without permission.
