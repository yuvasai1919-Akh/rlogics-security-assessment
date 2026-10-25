# Scan gate result: **FAIL**

- Source: `scripts/samples/trivy_critical_fixable.json`
- Policy: fail on >= `CRITICAL`, only-fixable=`True`, secrets block=`True`, today=`2026-10-24`
- Findings: 3 (BLOCK 1, EXCEPTED 0, WARN 2)

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 1 |

## BLOCK

| ID | Sev | Package | Installed | Fixed | Target | Reason |
|---|---|---|---|---|---|---|
| CVE-2099-0001 | CRITICAL | examplelib | 1.0.0 | 1.0.5 | requirements.txt | CRITICAL with fix 1.0.5 |

## WARN

| ID | Sev | Package | Installed | Fixed | Target | Reason |
|---|---|---|---|---|---|---|
| CVE-2099-0002 | HIGH | otherlib | 2.1.0 | 2.1.9 | requirements.txt | HIGH with fix 2.1.9 |
| CVE-2099-0003 | MEDIUM | midlib | 0.9.0 | - | requirements.txt | MEDIUM |
