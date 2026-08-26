# Enrollment Platform — AI Agent Implementation Guardrails

## 1. Authoritative sources

For implementation work, use the following sources in this order:

1. `docs/Enrollment_Platform_OpenAPI_Contract_Draft_v0.1.3.yaml`
   - executable HTTP/API contract
2. `docs/Enrollment_Platform_Enrollment_Protocol_Specification_v0.2.4.docx`
   - normative protocol semantics
3. `docs/Enrollment_Platform_OpenAPI_Contract_Draft_v0.1.3_README.md`
   - implementation and contract notes

Do not modify these controlled documents unless explicitly authorized.

If implementation appears to require changing the protocol or OpenAPI,
STOP and report the inconsistency instead of silently changing the design.

---

## 2. Architecture invariants

The following rules are mandatory.

### External exposure

- Reverse Proxy is the only externally exposed component.
- Enrollment API must not be directly exposed to external clients.
- Step CA must never be directly exposed to the Agent.
- Agent must never communicate directly with Step CA.

### Authority boundaries

- Enrollment API is the business-policy and authorization authority.
- Step CA is an internal certificate-signing engine only.
- Keycloak authenticates identities; domain authorization remains in Enrollment API.
- Authentication alone must never authorize certificate issuance.

### Device identity

- `device_id` is created server-side.
- `device_id` is the immutable logical identity of a device.
- Hostname, SMBIOS UUID, TPM identity, certificate serial and public key
  are attributes or historical relationships, not canonical device identity.
- TPM/EK replacement must never automatically rebind a device.

### Partner authorization

- `partner_id` supplied by a client is never trusted by itself.
- The server must resolve and validate the principal's current authorization.
- One principal may be authorized for multiple partners simultaneously.
- Do not add a single canonical `partner_id` to a principal/user entity.

### Certificate identity

- Subject, SAN, EKU, KeyUsage, validity and certificate profile are
  derived server-side.
- CSR extensions must never expand identity or authorization.
- The certificate private key must never be transmitted to or stored
  by Enrollment Platform.

---

## 3. Enrollment security invariants

Certificate issuance requires all applicable gates:

- authenticated/authorized principal or device;
- current partner eligibility;
- administrative approval where required;
- valid enrollment state;
- valid challenge;
- Proof-of-Possession;
- required TPM/attestation assurance;
- certificate profile authorization;
- final policy evaluation.

Do not bypass or collapse these checks for implementation convenience.

### State machine

Preserve the protocol state machine.

Important boundary:

`AUTHORIZED -> CA_REQUESTED`

`AUTHORIZED` means:
- authorization decision snapshot has been persisted;
- no CA side effect has occurred yet.

`CA_REQUESTED` is the authorization commit point after which CA side effects
are permitted.

Do not move CA calls before this boundary.

### Post-CA eligibility

`CERT_ISSUED` does not imply `CERT_DELIVERED`.

Eligibility and policy must be rechecked after CA issuance and before
certificate delivery.

A certificate that becomes ineligible after issuance must be preserved in
history and handled as non-deliverable/revoked according to protocol.

---

## 4. Retry and idempotency

Retries must never create blind duplicate issuance.

- Preserve `Idempotency-Key` semantics from the OpenAPI and Protocol.
- Same key + same fingerprint must recover the same operation/result.
- Same key + different fingerprint must fail.
- Consumed request tokens must never become valid again.

Opaque authentication tokens use non-reversible server-side verifiers.

For server-generated secrets returned by an originating response,
the protocol permits only the temporary encrypted Idempotency Replay Capsule
defined in Protocol v0.2.4.

The replay capsule:

- is encrypted using authenticated encryption;
- is temporary;
- is not an authentication verifier;
- must never be logged;
- must never be stored as plaintext;
- must never permit a second enrollment or token minting during replay.

### Replay Capsule AAD and recovery (CR-M5.6-001)

- Normative AAD v1 is the complete ordered originator-resource tuple defined by Protocol §6.4; `enrollment_id` is not universal and `idempotency_record_id` is never normative AAD.
- EffectiveScope remains the frozen M5.4 credential kind + opaque server-authenticated binding + uppercase method + route template + exact Idempotency-Key; no raw bearer/Authorization/client assertion substitutes.
- Same scope and fingerprint recover the exact original secret, never a replacement. Replay has no mutation or quota authority.
- Pre-onboarding replay uses the committed result snapshot for the original 201 body, ETag and Location; current-attempt correlation ID is excluded from scope/fingerprint/AAD and replay does not emit another `PREONBOARD_SUBMITTED` event.
- Permanent capsule loss is `409 IDEMPOTENCY_REPLAY_UNAVAILABLE`; transient protector failure is `503 DEPENDENCY_UNAVAILABLE`; fingerprint mismatch remains `409 IDEMPOTENCY_CONFLICT`.
- M5.4 Reserve for secret-originator execution must be inside the transaction-bound Unit of Work. NEW alone consumes Temporary Principal quota; never freeze OPEN-009 DB mechanics or CG-003 quantitative TTLs.
- M4 capability authentication remains read-only; credential issuance/verifier persistence and quota mutation are a separate lifecycle/write boundary.

---

## 5. TPM and Proof-of-Possession

### A1

`LOCAL_TPM_ASSERTED / A1` is not remote TPM attestation.

Client assertions such as:

- TPM ready;
- hardware-backed provider;
- private key non-exportable;
- Microsoft Platform Crypto Provider;

are local assertions only.

They must never elevate assurance to A2 or A3.

### A2/A3

Remote assurance requires verifier-backed TPM evidence according to
the relevant OPEN-004 artifacts.

Do not invent or freeze the internal TPM evidence wire format while
OPEN-004A remains open.

### JWS PoP

Enrollment PoP uses the protocol-defined JWS ES256 mechanism.

- verification key comes from CSR SPKI;
- do not trust JWK/JKU/X5U supplied by the client;
- bind enrollment, challenge version, nonce, CSR hash and public-key hash;
- reject algorithm confusion and unsupported algorithms.

---

## 6. mTLS architecture

Device mTLS terminates at the trusted Reverse Proxy.

The Enrollment API must not assume that the device client certificate
terminates directly on its Go HTTP listener.

The hop:

Reverse Proxy -> Enrollment API

must itself use authenticated mTLS with the authorized proxy service identity.

Client-certificate metadata is trustworthy only when:

1. external equivalent headers were stripped by the proxy;
2. the proxy validated the device certificate;
3. the Proxy -> API connection authenticated the expected proxy identity;
4. Enrollment API resolves certificate/device identity server-side.

Never trust client-supplied certificate metadata headers directly.

---

## 7. Administrative authorization

A valid `AdminOIDC` token does not mean universal administrative authorization.

Each sensitive operation must pass domain authorization and policy.

Where the OpenAPI specifies scopes, enforce them.

Where authorization is explicitly OPEN/policy-defined, do not invent a broad
administrator bypass.

High-impact operations such as rebinding and broad revocation may additionally
require step-up or dual-control according to policy.

---

## 8. OpenAPI implementation rules

The current controlled OpenAPI contract defines exactly the current contracted operations.

- Do not invent endpoints.
- Do not delete endpoints.
- Do not rename operations.
- Do not loosen request validation.
- Request schemas marked closed must reject unknown sensitive fields.
- Response handling must remain forward-compatible.
- Unknown response enum/string values must never be interpreted as success.

Conditional authentication rules must be implemented manually where OpenAPI
cannot enforce them structurally.

Examples:

`POST /v1/enrollments`

- INITIAL -> RequestAccessToken
- RENEWAL -> DeviceMTLS
- REKEY -> DeviceMTLS

`POST /v1/enrollments/{id}/complete`

- INSTALLED -> DeviceMTLS
- FAILED -> EnrollmentAccessToken

Wrong authentication/body pairings must fail closed.

---

## 9. HTTP semantics

Preserve the OpenAPI semantics for:

- RFC 9457 Problem Details;
- `X-Correlation-ID`;
- `Idempotency-Key`;
- `ETag`;
- `If-Match`;
- `412 Precondition Failed`;
- `WWW-Authenticate`;
- `Location`;
- payload-size limits;
- cursor pagination.

Do not replace standard HTTP semantics with custom fields merely for coding
convenience.

---

## 10. Persistence rules

Until PostgreSQL implementation is explicitly requested:

- define interfaces/ports;
- use test doubles or in-memory adapters only where needed;
- do not hardcode persistence decisions into domain logic.

When PostgreSQL is implemented, concurrency guarantees required by the
protocol must be transactional.

Certificate issuance history must remain immutable.

Do not overwrite historical certificates during renewal/rekey.

---

## 11. External adapters

Treat external dependencies through interfaces/adapters:

- Keycloak
- PostgreSQL
- Step CA
- Attestation Verifier
- Partner/SAP source
- observability exporters

Do not couple domain logic directly to vendor SDKs.

---

## 12. OPEN items

OPEN items remain OPEN until explicitly closed by their designated
specification/POC.

Do not silently choose final values for:

- Agent login flow;
- TPM evidence wire format;
- verifier implementation;
- TPM trust anchors;
- assurance policy;
- certificate validity/renewal/overlap;
- relying-party revocation behavior;
- physical PostgreSQL locking/schema choices;
- operational SLOs/HA/retention.

Parameterize or define interfaces instead.

---

## 13. Coding requirements

Language: Go.

General rules:

- keep HTTP handlers thin;
- business rules belong in application/domain layers;
- use explicit errors;
- propagate `context.Context`;
- do not use global mutable state;
- never log credentials, tokens, private keys or TPM private material;
- preserve correlation identifiers;
- prefer deterministic tests;
- keep generated OpenAPI code separate from handwritten domain code.

Generated files should not be manually edited.

---

## 14. Required validation

Before declaring a milestone complete, run:

```text
go fmt ./...
go vet ./...
go test ./...
go build ./...
```
If additional linters/tools are configured, run them as well.

Report:

- commands executed;
- test results;
- build results;
- generated files;
- architectural questions;
- deviations from OpenAPI/Protocol;
- unresolved TODOs.

---

## 15. Change-control rule

If a requested implementation conflicts with:

- OpenAPI v0.1.3;
- Protocol v0.2.4;
- an architecture invariant in this file;

do not silently resolve the conflict.

Report:

1. the conflicting requirement;
2. affected file/section;
3. implementation consequence;
4. possible alternatives.

Wait for an architectural decision before changing the controlled contract.
