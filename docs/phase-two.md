# Sentinel validation and intelligence phase

This phase connects Sentinel's existing collectors, research pipeline, job queue,
and evidence store into a measurable assessment lifecycle.

## Lifecycle

1. An engagement defines exact domains, IP addresses, or CIDRs and whether active
   checks are permitted.
2. `hunt` runs reviewed adapters only. Every target passes the scope gate and
   active checks require an explicit approval flag.
3. Normalizers create entities, relationships, and fingerprinted findings.
4. Validation correlates independent sources and repeated observations. It does
   not claim confirmation from a single scanner result.
5. Intelligence scores findings and builds bounded relationship paths.
6. Reports and the operator dashboard expose evidence, validation, risk,
   remediation, coverage, and workflow state.
7. Schedules enqueue new workflows through the same policy gates. The daemon has
   runtime/job bounds, a stop file, and the engagement kill switch.

## API assessment

The OpenAPI engine is offline. It reviews operation authentication declarations,
object identifier parameters, and permissive request schemas. Any declared
server must be inside engagement scope. Future request generation must continue
to use reviewed adapters and harmless validation profiles.

## Research and exploit validation

Coverage-guided research remains restricted to engagements marked as isolated
labs. Crash evidence must be reproduced and accompanied by sanitizer evidence
before novelty scoring. Production reports use non-destructive evidence; they do
not perform credential harvesting, persistence, destructive actions, automated
lateral movement, or unrestricted payload execution.

## Assurance

Sentinel measures coverage and confidence. It cannot guarantee that every known
or unknown vulnerability will be discovered. The executable provenance command
records current adapter hashes so operators can pin reviewed binaries and detect
unexpected changes in controlled deployments.
