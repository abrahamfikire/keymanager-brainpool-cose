# ECC Key Lifecycle, Signing Fallback, and JWKS Behavior

## Overview
This document summarizes the implemented changes for ECC SECP256R1 signing keys and the expected behavior across the Keymanager and Signature services.

- Introduced explicit dual-key lifecycle for SECP256R1 family:
  - `EC_SECP256R1_SIGN_PRIMARY` (active/preferred)
  - `EC_SECP256R1_SIGN_SECONDARY` (standby/fallback)
- Prevented auto-generation for SECP256R1 family in read-only GET endpoints and JWKS.
- Implemented signing fallback (PRIMARY → SECONDARY) for:
  - `signCredential`
  - `jwtSign`
- Added JWKS wildcard support (prefix match) and safe aggregation (skip missing/unavailable refs).
- Access control (optional) for `/signCredential` via Keycloak role.

## Key Reference IDs
- `EC_SECP256R1_SIGN_PRIMARY`: Preferred active signing key
- `EC_SECP256R1_SIGN_SECONDARY`: Standby signing key used during rotation
- `EC_SECP256R1_SIGN`: Legacy/base ref (kept for compatibility but not auto-generated via GET)
- Other ECC refs supported as-is (e.g., `EC_BRAINPOOLP256R1_SIGN`) and non-ECC refs remain unchanged

## Endpoint Behavior

### Key Generation
- `POST /v1/keymanager/generateECSignKey/{objectType}`
  - Explicit generation only. For SECP256R1 family, first-time creation or re-generation after expiry is allowed.
  - Rotation while a current valid key exists is blocked for SECP256R1 family.

### Certificate Retrieval (Read-only)
- `GET /v1/keymanager/getCertificate`
- `GET /v1/keymanager/getAllCertificates`
  - For SECP256R1 family: no auto-generation; errors if missing/unavailable.
  - For other refs: legacy behavior is preserved.

### JWKS
- `GET /v1/keymanager/jwks?applicationId=APP&referenceId=EC_SECP256R1_SIGN*`
  - Supports wildcard suffix `*` as prefix match.
  - Aggregates all matching refs that are available (e.g., PRIMARY/SECONDARY).
  - Skips refs that would trigger generation or are unavailable; no failure for the entire request.

### Signing (Data, JWT)
- `POST /v1/keymanager/signCredential`
  - If refId ∈ {EC_SECP256R1_SIGN, PRIMARY, SECONDARY}:
    - Try `EC_SECP256R1_SIGN_PRIMARY` first
    - If unavailable/expired, try `EC_SECP256R1_SIGN_SECONDARY`
  - Otherwise: use the given refId directly (legacy behavior)
  - Input message is Base64-encoded binary (decoded before signing); output is Base64 of raw (r||s) signature.

- `POST /signature/jwtSign`
  - Same fallback priority for SECP256R1 family (PRIMARY → SECONDARY).
  - `kid` set to the actual key used (derived from uniqueIdentifier).

- `POST /signature/verifyCredential`
  - Base64 message and Base64 signature expected; converts signature to DER for verification.
  - Certificate fetched by referenceId; for SECP256R1 family, rely on the provided ref (or extend to fallback if desired).

### Access Control (Optional)
- `/signCredential` can be restricted via Keycloak role (e.g., `fayda_cred_client`) using `@PreAuthorize`.
- Ensure method security is enabled in Spring and role mapping matches your realm configuration.

## Rotation Model (Recommended)
1. Generate `EC_SECP256R1_SIGN_SECONDARY` and publish via JWKS.
2. Switch traffic to `PRIMARY` when ready (promote SECONDARY → PRIMARY operationally).
3. Keep old key available for verification during grace period.
4. Retire old key after validation window.

This model avoids downtime and enables graceful rollover.

## Test Scenarios (High-level)

1) Explicit Generation – PRIMARY
- Generate `EC_SECP256R1_SIGN_PRIMARY` via `/generateECSignKey/CERTIFICATE`.
- Expect 200 and certificate available in HSM/DB.

2) Explicit Generation – SECONDARY
- Generate `EC_SECP256R1_SIGN_SECONDARY` similarly.
- Expect 200; JWKS should list both if requested via wildcard.

3) GET Certificates – No Auto-Gen
- With no current SECP256R1 key: GET `/getCertificate`/`/getAllCertificates` should error (no auto-generation).

4) JWKS Wildcard – Aggregate Available
- If `EC_SECP256R1_SIGN` is expired/missing but PRIMARY/SECONDARY exist:
- GET `/jwks?referenceId=EC_SECP256R1_SIGN*` should return entries for PRIMARY/SECONDARY.

5) signCredential – Fallback
- With PRIMARY valid: signs with PRIMARY (`kid` points to PRIMARY).
- With PRIMARY expired/missing and SECONDARY valid: signs with SECONDARY.
- Verify signature with `/verifyCredential` using the Base64 message and signature.

6) jwtSign – Fallback
- Same as (5) but for JWT API; verify token using JWKS.

7) Non-SECP256R1 Refs Unchanged
- Use refs like `SIGN`, RSA, ED25519; expect direct behavior without fallback.

8) Access Control (if enabled)
- `/signCredential` requires token with `fayda_cred_client` role; without, expect 403.

## Notes & Constraints
- Auto-generation is disabled for read-only endpoints and JWKS for SECP256R1 family.
- JWKS wildcard uses enum name prefix matching and skips failing refs.
- Ensure your clients handle `kid` correctly and refresh JWKS periodically.

## Example cURL

- JWKS (Wildcard):
```
curl "http://localhost:8088/v1/keymanager/jwks?applicationId=APP&referenceId=EC_SECP256R1_SIGN*"
```

- Generate PRIMARY:
```
curl -X POST "http://localhost:8088/v1/keymanager/generateECSignKey/CERTIFICATE" \
  -H "Content-Type: application/json" \
  -d '{"applicationId":"APP","referenceId":"EC_SECP256R1_SIGN_PRIMARY"}'
```

- Sign Credential:
```
curl -X POST "http://localhost:8088/v1/keymanager/signCredential" \
  -H "Content-Type: application/json" \
  -d '{"id":"req1","request":{"message":"BASE64_DATA","applicationId":"APP","referenceId":"EC_SECP256R1_SIGN"}}'
```

- Verify Credential:
```
curl -X POST "http://localhost:8088/v1/keymanager/verifyCredential" \
  -H "Content-Type: application/json" \
  -d '{"id":"req2","request":{"message":"BASE64_DATA","signature":"BASE64_SIG","applicationId":"APP","referenceId":"EC_SECP256R1_SIGN"}}'
```
