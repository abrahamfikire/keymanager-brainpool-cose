# SignCredential Security Test Scenarios & Test Data

## 🧪 **Comprehensive Test Suite for Security Fixes**

This document provides detailed test scenarios and test data to validate all implemented security fixes in the `signCredential` method.

## 📋 **Test Categories**

### **1. Input Validation Tests**
### **2. Access Control Tests** 
### **3. Certificate Validation Tests**
### **4. Security Logging Tests**
### **5. Signature Generation Tests**
### **6. Error Handling Tests**
### **7. Performance Tests**

---

## 🔍 **1. INPUT VALIDATION TESTS**

### **Test Case 1.1: Null Request DTO**
```json
// Test Data
null

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Request DTO cannot be null"
}
```

### **Test Case 1.2: Empty Message**
```json
// Test Data
{
  "id": "test-request-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Message cannot be null or empty"
}
```

### **Test Case 1.3: Null Message**
```json
// Test Data
{
  "id": "test-request-002",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": null,
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Message cannot be null or empty"
}
```

### **Test Case 1.4: Invalid Base64 Format**
```json
// Test Data
{
  "id": "test-request-003",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "Invalid@Base64#Format!",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid Base64 format in message"
}
```

### **Test Case 1.5: Malformed Base64 (Wrong Padding)**
```json
// Test Data
{
  "id": "test-request-004",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ",  // Missing padding
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid Base64 format in message"
}
```

### **Test Case 1.6: Message Size Exceeds Limit (1MB)**
```json
// Test Data
{
  "id": "test-request-005",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "VERY_LONG_BASE64_STRING_OVER_1MB...", // 1MB+ string
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Message size exceeds maximum allowed limit of 1MB"
}
```

### **Test Case 1.7: Invalid ApplicationId Format**
```json
// Test Data
{
  "id": "test-request-006",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "INVALID@APP#ID!",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid ApplicationId format"
}
```

### **Test Case 1.8: Invalid ReferenceId Format**
```json
// Test Data
{
  "id": "test-request-007",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "INVALID@REF#ID!"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid ReferenceId format"
}
```

### **Test Case 1.9: Valid Input (Success Case)**
```json
// Test Data
{
  "id": "test-request-008",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 200 OK
{
  "id": "test-request-008",
  "version": "1.0",
  "responsetime": "2024-01-15T10:30:01.000Z",
  "response": {
    "signatureData": "base64-encoded-signature",
    "kid": "base64-encoded-key-id"
  }
}
```

---

## 🔐 **2. ACCESS CONTROL TESTS**

### **Test Case 2.1: Unauthorized ApplicationId**
```json
// Test Data
{
  "id": "test-request-009",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "UNAUTHORIZED_APP",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 403 Forbidden
{
  "errorCode": "KER-JWS-108",
  "errorMessage": "Signing data not allowed for the authenticated token."
}
```

### **Test Case 2.2: Valid ApplicationId with Access**
```json
// Test Data
{
  "id": "test-request-010",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 200 OK (if user has access to KERNEL application)
```

---

## 📜 **3. CERTIFICATE VALIDATION TESTS**

### **Test Case 3.1: Expired Certificate**
```json
// Test Data (Use expired certificate scenario)
{
  "id": "test-request-011",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "EXPIRED_CERT_APP",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-107",
  "errorMessage": "Signature verification certificate not valid."
}
```

### **Test Case 3.2: Revoked Certificate**
```json
// Test Data (Use revoked certificate scenario)
{
  "id": "test-request-012",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "REVOKED_CERT_APP",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-107",
  "errorMessage": "Signature verification certificate not valid."
}
```

### **Test Case 3.3: Valid Certificate**
```json
// Test Data
{
  "id": "test-request-013",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 200 OK (if certificate is valid)
```

---

## 📋 **4. SECURITY LOGGING TESTS**

### **Test Case 4.1: Verify Sensitive Information Not Logged**
```bash
# Test Steps:
1. Set log level to INFO
2. Make a valid request
3. Check logs for sensitive information

# Expected Log Content (INFO level):
- "Received signCredential request. RequestId: test-request-014, ApplicationId: KERNEL"
- "Credential signing completed successfully for applicationId: KERNEL"

# Expected Log Content (DEBUG level only):
- "Certificate validation completed for applicationId: KERNEL, keyId: [key-id]"
- "Certificate algorithm: EC"
- "Certificate valid from: [date] to: [date]"

# NOT Expected in INFO logs:
- Certificate Subject
- Certificate Serial Number
- Private key information
```

### **Test Case 4.2: Verify Session ID Tracking**
```bash
# Test Steps:
1. Make multiple requests
2. Check that each request has consistent session ID tracking

# Expected Log Pattern:
[INFO] [SignatureSessionId] [SIGN_CREDENTIAL_CONTROLLER] Received signCredential request...
[INFO] [SignatureSessionId] [SIGN_CREDENTIAL] Credential signing completed successfully...
```

---

## 🔐 **5. SIGNATURE GENERATION TESTS**

### **Test Case 5.1: Valid Signature Generation**
```json
// Test Data
{
  "id": "test-request-015",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 200 OK
{
  "response": {
    "signatureData": "64-character-base64-string", // Exactly 64 characters for P-256
    "kid": "base64-encoded-key-id"
  }
}

// Validation:
- signatureData should be exactly 64 characters when decoded
- signatureData should be valid Base64
- kid should be present and valid
```

### **Test Case 5.2: Invalid Signature Size (Simulated)**
```bash
# Test Steps:
1. Mock the signature generation to return invalid size
2. Verify error handling

# Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-104",
  "errorMessage": "Invalid signature format: unexpected size [size]"
}
```

### **Test Case 5.3: DER to RAW Conversion Failure**
```bash
# Test Steps:
1. Mock DER signature with invalid format
2. Verify conversion error handling

# Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-104",
  "errorMessage": "Failed to convert signature format: [error details]"
}
```

---

## 🚨 **6. ERROR HANDLING TESTS**

### **Test Case 6.1: Cryptographic Exception**
```bash
# Test Steps:
1. Mock cryptographic operations to throw exceptions
2. Verify error handling

# Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-104",
  "errorMessage": "Failed to generate signature: [error details]"
}

# Verify:
- No sensitive information in error message
- Proper error code returned
- Exception logged at ERROR level
```

### **Test Case 6.2: HSM Provider Exception**
```bash
# Test Steps:
1. Mock HSM provider to throw exceptions
2. Verify error handling

# Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-104",
  "errorMessage": "Error - Unable to sign the data."
}

# Verify:
- Generic error message (no HSM details exposed)
- Proper error code
- Exception logged securely
```

### **Test Case 6.3: Network/Timeout Exception**
```bash
# Test Steps:
1. Simulate network timeout during certificate retrieval
2. Verify error handling

# Expected Result
HTTP 500 Internal Server Error
{
  "errorCode": "KER-JWS-104",
  "errorMessage": "Error - Unable to sign the data."
}
```

---

## ⚡ **7. PERFORMANCE TESTS**

### **Test Case 7.1: Large Message Performance**
```json
// Test Data (Approaching 1MB limit)
{
  "id": "test-request-016",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "LARGE_BASE64_STRING_APPROACHING_1MB_LIMIT...",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Results:
- Response time: < 100ms additional overhead
- Memory usage: No significant increase
- CPU usage: < 5% additional
```

### **Test Case 7.2: Concurrent Request Performance**
```bash
# Test Steps:
1. Send 100 concurrent requests
2. Measure response times and resource usage

# Expected Results:
- Average response time: < 200ms
- 95th percentile: < 500ms
- No memory leaks
- No resource exhaustion
```

### **Test Case 7.3: Stress Test**
```bash
# Test Steps:
1. Send 1000 requests over 1 minute
2. Monitor system resources

# Expected Results:
- No system crashes
- Response times remain consistent
- Memory usage stable
- CPU usage < 80%
```

---

## 🧪 **8. INTEGRATION TESTS**

### **Test Case 8.1: End-to-End Valid Flow**
```bash
# Test Steps:
1. Send valid request
2. Verify complete flow works
3. Verify response format
4. Verify signature can be verified

# Test Data:
{
  "id": "integration-test-001",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

# Expected Results:
- HTTP 200 OK
- Valid signature returned
- Signature can be verified with public key
- All logs contain expected information
```

### **Test Case 8.2: Error Flow Integration**
```bash
# Test Steps:
1. Send invalid request
2. Verify error response format
3. Verify error logging
4. Verify no sensitive information leaked

# Test Data:
{
  "id": "integration-test-002",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "INVALID_BASE64!",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

# Expected Results:
- HTTP 400 Bad Request
- Proper error code and message
- No sensitive information in response
- Error logged appropriately
```

---

## 📊 **9. SECURITY PENETRATION TESTS**

### **Test Case 9.1: SQL Injection Attempt**
```json
// Test Data
{
  "id": "test-request-017",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "KERNEL'; DROP TABLE users; --",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid ApplicationId format"
}
```

### **Test Case 9.2: XSS Attempt**
```json
// Test Data
{
  "id": "test-request-018",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "<script>alert('XSS')</script>",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid Base64 format in message"
}
```

### **Test Case 9.3: Path Traversal Attempt**
```json
// Test Data
{
  "id": "test-request-019",
  "version": "1.0",
  "requesttime": "2024-01-15T10:30:00.000Z",
  "request": {
    "message": "SGVsbG8gV29ybGQ=",
    "applicationId": "../../etc/passwd",
    "referenceId": "SIGN"
  }
}

// Expected Result
HTTP 400 Bad Request
{
  "errorCode": "KER-JWS-102",
  "errorMessage": "Invalid ApplicationId format"
}
```

---

## 🔧 **10. TEST DATA GENERATORS**

### **Valid Test Data Generator**
```javascript
// JavaScript function to generate valid test data
function generateValidTestData() {
  const validMessages = [
    "SGVsbG8gV29ybGQ=",  // "Hello World"
    "VGVzdCBNZXNzYWdl",  // "Test Message"
    "Q3JlZGVudGlhbCBEYXRh",  // "Credential Data"
    "U2lnbmVkIERvY3VtZW50"   // "Signed Document"
  ];
  
  const validAppIds = ["KERNEL", "REGISTRATION", "AUTH", "ID_REPO"];
  const validRefIds = ["SIGN", "VERIFY", "ENCRYPT", "DECRYPT"];
  
  return {
    id: `test-request-${Date.now()}`,
    version: "1.0",
    requesttime: new Date().toISOString(),
    request: {
      message: validMessages[Math.floor(Math.random() * validMessages.length)],
      applicationId: validAppIds[Math.floor(Math.random() * validAppIds.length)],
      referenceId: validRefIds[Math.floor(Math.random() * validRefIds.length)]
    }
  };
}
```

### **Invalid Test Data Generator**
```javascript
// JavaScript function to generate invalid test data
function generateInvalidTestData(type) {
  const baseRequest = {
    id: `test-request-${Date.now()}`,
    version: "1.0",
    requesttime: new Date().toISOString(),
    request: {
      message: "SGVsbG8gV29ybGQ=",
      applicationId: "KERNEL",
      referenceId: "SIGN"
    }
  };
  
  switch(type) {
    case 'null_message':
      baseRequest.request.message = null;
      break;
    case 'empty_message':
      baseRequest.request.message = "";
      break;
    case 'invalid_base64':
      baseRequest.request.message = "Invalid@Base64#Format!";
      break;
    case 'large_message':
      baseRequest.request.message = "A".repeat(1048577); // > 1MB
      break;
    case 'invalid_app_id':
      baseRequest.request.applicationId = "INVALID@APP#ID!";
      break;
    case 'invalid_ref_id':
      baseRequest.request.referenceId = "INVALID@REF#ID!";
      break;
  }
  
  return baseRequest;
}
```

---

## 📋 **11. TEST EXECUTION CHECKLIST**

### **Pre-Test Setup**
- [ ] Test environment configured
- [ ] Valid certificates installed
- [ ] Invalid certificates available for testing
- [ ] Logging configured at appropriate levels
- [ ] Monitoring tools active

### **Test Execution**
- [ ] Input validation tests (9 test cases)
- [ ] Access control tests (2 test cases)
- [ ] Certificate validation tests (3 test cases)
- [ ] Security logging tests (2 test cases)
- [ ] Signature generation tests (3 test cases)
- [ ] Error handling tests (3 test cases)
- [ ] Performance tests (3 test cases)
- [ ] Integration tests (2 test cases)
- [ ] Security penetration tests (3 test cases)

### **Post-Test Validation**
- [ ] All expected results achieved
- [ ] No unexpected errors
- [ ] Performance within acceptable limits
- [ ] Security requirements met
- [ ] Logs contain expected information
- [ ] No sensitive information leaked

---

## 🎯 **12. SUCCESS CRITERIA**

### **Security Requirements**
- ✅ All input validation tests pass
- ✅ Access control properly enforced
- ✅ Certificate validation working
- ✅ No information disclosure in logs
- ✅ Error handling secure
- ✅ Penetration tests blocked

### **Functional Requirements**
- ✅ Valid requests processed successfully
- ✅ Invalid requests rejected appropriately
- ✅ Response format correct
- ✅ Signatures generated correctly
- ✅ Performance within limits

### **Compliance Requirements**
- ✅ OWASP Top 10 vulnerabilities addressed
- ✅ NIST security controls implemented
- ✅ ISO 27001 requirements met
- ✅ Audit trail complete

This comprehensive test suite ensures all security fixes are working correctly and the system is secure against various attack vectors.
