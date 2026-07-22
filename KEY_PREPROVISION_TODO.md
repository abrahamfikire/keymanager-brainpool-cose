# Key Pre-Provisioning Enhancement: TODOs

This document tracks the steps required to enable pre-provisioning of multiple, non-overlapping keys for the same application ID and reference ID in the key manager service.

## Goal
Allow clients to generate multiple keys for the same (app ID, ref ID) pair, each with a custom, non-overlapping validity window (e.g., for future years), by specifying validity start and end times.

---

## TODOs

1. **Add `validFrom` and `validTo` fields to `KeyPairGenerateRequestDto`**
   - Allow clients to specify custom validity windows for key generation.
   - Fields: `private LocalDateTime validFrom;`, `private LocalDateTime validTo;`

2. **Update `KeymanagerController` to accept and document `validFrom` and `validTo`**
   - Ensure endpoints like `/generateMasterKey` and `/generateECSignKey` accept these fields.
   - Update API documentation/comments to reflect the new parameters.

3. **Update `KeymanagerServiceImpl` to use `validFrom` and `validTo`**
   - Use these fields for key validity if provided, otherwise fall back to the current logic (current time + policy duration).

4. **Implement overlap check in `KeymanagerServiceImpl`**
   - Before creating a new key, check for overlapping validity windows with existing keys for the same app ID and ref ID.
   - Reject the request if overlap is found, with a clear error message.

5. **Test multi-key generation**
   - Generate multiple keys for the same app ID and ref ID with consecutive, non-overlapping validity periods.
   - Verify correct behavior and error handling for overlapping requests.

---

**Note:**
- This change will allow pre-provisioning of keys for future use, supporting scenarios like scheduled key rollovers or compliance with long-term cryptographic policies.
