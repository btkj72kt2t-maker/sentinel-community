# Sentinel Proof Engine

The Proof Engine turns scanner observations into bounded evidence workflows. It
does not contain autonomous live-target exploitation.

## Module contract

Every module declares its vulnerability family, execution mode, maximum request
count, possible side effects, required evidence, cleanup procedure, and matching
keywords. The registry is code-reviewed and cannot load arbitrary entrypoints.

Supported foundations cover authorization, sessions, inert browser markers,
injection differentials, loopback callback observation, file-policy review,
cache behavior, API role matrices, and business-logic invariants.

## Evidence sources

- Offline HTTP baseline/variant comparisons
- Expected-versus-observed authorization matrices
- Short-lived loopback callback events
- Existing scanner and intelligence findings
- Hashed isolated-lab proof files

Sensitive header values and fields with names such as token, cookie, password,
secret, authorization, and API key are removed from generated packages.

## Execution boundary

Planning is non-executing. Offline modules process operator-supplied evidence.
Active and lab-capable modules use existing engagement policy checks. Lab modules
require `lab_mode`, active enablement where applicable, and explicit approval.
The callback server binds only to loopback and expires tokens automatically.

Sentinel does not provide data extraction, remote shells, persistence, evasion,
credential collection, destructive payloads, or automatic lateral movement.
