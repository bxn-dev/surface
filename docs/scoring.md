# Surface Exposure Score

Surface reports score model `1.0` on a `0–100` scale. A higher value means fewer **detected** external exposure and configuration concerns. It is not CVSS, a probability of compromise, certification, or proof of security.

## Deterministic calculation

The model starts at 100 and applies one deduction for each unique `(finding rule ID, target)` pair:

| Finding severity | Deduction |
| --- | ---: |
| Informational | 0 |
| Low | 2 |
| Medium | 7 |
| High | 20 |
| Critical | 35 |

Deductions are sorted by stable identity and the final value is clamped to `0–100`. Duplicate instances with the same rule ID and target are not counted twice. The report includes every deduction, its point value, target, and supporting finding ID.

## Classification

| Value | Classification |
| --- | --- |
| 85–100 | Favorable |
| 65–84 | Review |
| 35–64 | Elevated |
| 0–34 | Critical |

These labels prioritize review; they do not declare a target secure or compromised.

## Completeness

`incomplete` is independent of the numeric value. Partial, interrupted, failed, or not-started scans set it to true. Missing observations never produce deductions, so an incomplete score must not be compared as though it covered the same evidence.

Changing weights or interpretation requires a new score-model version. Historical reports retain their original score and model version.
