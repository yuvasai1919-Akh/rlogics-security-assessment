# Legacy Kyverno ClusterPolicy versions

Kyverno deprecated `ClusterPolicy` in 1.17; removal is planned for v1.20 (scheduled around
Oct/Nov 2026). These files work on Kyverno <= 1.19 only. The current-format equivalents are one
directory up (`ValidatingPolicy`) and in `../examples/` (`ImageValidatingPolicy`).

Good interview point: "I noticed the policy API I was about to use is being removed, checked the
release notes, and built on the replacement" - then explain what CEL-based policies change
(expressions instead of patterns, `validationActions` instead of `validationFailureAction`, separate
kinds for validate / mutate / generate / image verification).

Apply manually if you are on an older Kyverno: `kubectl apply -f kubernetes/policies/legacy/`
(skip `clusterpolicy-verify-image-signature.yaml` until you paste a real public key).
