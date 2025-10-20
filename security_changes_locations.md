# Security Changes - File Locations and Line Numbers

## 📍 **Primary Files to Modify**

### **1. Main Service Implementation**
**File:** `kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/signature/service/impl/SignatureServiceImpl.java`

#### **🔴 CRITICAL: signCredential Method (Lines 1742-1781)**
```java
// CURRENT VULNERABLE CODE (Lines 1742-1781):
@Override
public SignatureResponseDto signCredential(SignCredentialRequestDto requestDto) {
    String base64Message = requestDto.getMessage();                    // Line 1743 - NO VALIDATION
    String applicationId = requestDto.getApplicationId();              // Line 1744 - NO VALIDATION  
    String referenceId = requestDto.getReferenceId();                  // Line 1745 - NO VALIDATION
    String timestamp = DateUtils.getUTCCurrentDateTimeString();        // Line 1746
    SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp); // Line 1747 - NO CERT VALIDATION
    PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey(); // Line 1748
    String providerName = certificateResponse.getProviderName();       // Line 1749

    // VULNERABLE LOGGING (Lines 1752-1755):
    X509Certificate cert = certificateResponse.getCertificateEntry().getChain()[0];
    LOGGER.info("signCredential", "CERT_DEBUG", "", "Certificate Subject: {}", cert.getSubjectX500Principal());     // Line 1753 - INFO DISCLOSURE
    LOGGER.info("signCredential", "CERT_DEBUG", "", "Certificate Serial Number: {}", cert.getSerialNumber());      // Line 1754 - INFO DISCLOSURE
    LOGGER.info("signCredential", "CERT_DEBUG", "", "Certificate Public Key Algorithm: {}", cert.getPublicKey().getAlgorithm()); // Line 1755 - INFO DISCLOSURE

    String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier()); // Line 1757
    try {
        byte[] messageBytes = Base64.decodeBase64(base64Message);       // Line 1760 - NO BASE64 VALIDATION
        Signature signature = (providerName != null && !providerName.isEmpty()) // Lines 1763-1765
                ? Signature.getInstance("SHA256withECDSA", providerName)
                : Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);                                // Line 1766
        signature.update(messageBytes);                                // Line 1767
        byte[] derSignature = signature.sign();                        // Line 1768
        byte[] rawSignature = derToRaw(derSignature, 32);              // Line 1771 - NO BOUNDS CHECKING
        String signatureBase64 = Base64.encodeBase64String(rawSignature); // Line 1772
        SignatureResponseDto response = new SignatureResponseDto();    // Line 1773
        response.setSignatureData(signatureBase64);                    // Line 1774
        response.setKid(keyId);                                        // Line 1775
        return response;                                               // Line 1776
    } catch (Exception e) {                                            // Line 1777 - GENERIC ERROR HANDLING
        LOGGER.error("signCredential", "SIGN_CREDENTIAL", "", "Error signing credential message", e); // Line 1778
        throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(), SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e); // Line 1779
    }
}
```

#### **🔧 REQUIRED CHANGES:**

**1. Add Input Validation (After Line 1742):**
```java
// ADD: Input validation method calls
validateInputParameters(requestDto);
validateAccessControl(applicationId);
```

**2. Add Certificate Validation (After Line 1747):**
```java
// ADD: Missing certificate validation
keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), 
    DateUtils.parseUTCToDate(timestamp));
```

**3. Replace Vulnerable Logging (Lines 1752-1755):**
```java
// REPLACE: Information disclosure logging with secure logging
logCertificateInfoSecurely(certificateResponse, applicationId, sessionId);
```

**4. Add Safe Signature Generation (Replace Lines 1758-1776):**
```java
// REPLACE: Unsafe signature generation with secure version
byte[] signature = generateSecureSignature(messageBytes, privateKey, providerName);
byte[] rawSignature = convertDerToRawSafely(signature);
```

**5. Enhance Error Handling (Replace Lines 1777-1780):**
```java
// REPLACE: Generic error handling with specific error handling
} catch (RequestException | SignatureFailureException e) {
    throw e;
} catch (Exception e) {
    // Enhanced error handling
}
```

#### **🆕 NEW METHODS TO ADD:**

**Add after Line 1826 (after rawToDer method):**
```java
// ADD: Input validation methods
private void validateInputParameters(SignCredentialRequestDto requestDto) { ... }
private void validateAccessControl(String applicationId) { ... }
private void logCertificateInfoSecurely(...) { ... }
private byte[] generateSecureSignature(...) { ... }
private byte[] convertDerToRawSafely(...) { ... }
private boolean isValidBase64(String base64String) { ... }
private boolean isValidApplicationId(String applicationId) { ... }
private boolean isValidReferenceId(String referenceId) { ... }
```

#### **🔧 ENHANCE EXISTING METHODS:**

**1. Enhance derToRaw Method (Lines 1599-1609):**
```java
// CURRENT: Lines 1599-1609
public static byte[] derToRaw(byte[] der, int keySizeBytes) throws IOException {
    ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
    // ... existing code
}

// ENHANCE: Add input validation
public static byte[] derToRaw(byte[] der, int keySizeBytes) throws IOException {
    // ADD: Input validation
    if (der == null || der.length == 0) {
        throw new IllegalArgumentException("DER signature cannot be null or empty");
    }
    if (keySizeBytes <= 0 || keySizeBytes > 64) {
        throw new IllegalArgumentException("Invalid key size: " + keySizeBytes);
    }
    // ... existing code
}
```

### **2. Controller Layer**
**File:** `kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/signature/controller/SignatureController.java`

#### **🔧 ENHANCE: signCredential Endpoint (Lines 349-358)**
```java
// CURRENT: Lines 349-358
@ResponseBody
@PostMapping("/signCredential")
@ApiOperation(value = "Sign a credential message using ECDSA", notes = "Signs a credential message using the HSM-backed key for the given application and reference ID.")
public ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> signCredential(
        @RequestBody @Valid io.mosip.kernel.core.http.RequestWrapper<io.mosip.kernel.signature.dto.SignCredentialRequestDto> requestDto) {
    io.mosip.kernel.signature.dto.SignatureResponseDto responseDto = service.signCredential(requestDto.getRequest());
    io.mosip.kernel.core.http.ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> response = new io.mosip.kernel.core.http.ResponseWrapper<>();
    response.setResponse(responseDto);
    return response;
}
```

**ENHANCE: Add comprehensive logging and error handling:**
```java
// ADD: Enhanced controller with logging
@ResponseBody
@PostMapping("/signCredential")
@ApiOperation(value = "Sign a credential message using ECDSA", notes = "Signs a credential message using the HSM-backed key for the given application and reference ID.")
public ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> signCredential(
        @RequestBody @Valid io.mosip.kernel.core.http.RequestWrapper<io.mosip.kernel.signature.dto.SignCredentialRequestDto> requestDto) {
    
    String sessionId = SignatureConstant.SESSIONID;
    LOGGER.info(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
        "Received signCredential request. RequestId: {}, ApplicationId: {}", 
        requestDto.getId(), requestDto.getRequest().getApplicationId());
    
    try {
        io.mosip.kernel.signature.dto.SignatureResponseDto responseDto = service.signCredential(requestDto.getRequest());
        io.mosip.kernel.core.http.ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> response = new io.mosip.kernel.core.http.ResponseWrapper<>();
        response.setResponse(responseDto);
        
        LOGGER.info(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
            "SignCredential request completed successfully");
        
        return response;
    } catch (Exception e) {
        LOGGER.error(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
            "Exception in signCredential controller: {}", e.getMessage(), e);
        throw e;
    }
}
```

### **3. DTO Validation Enhancement**
**File:** `kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/signature/dto/SignCredentialRequestDto.java`

#### **🔧 ENHANCE: Add Validation Annotations (Lines 13-22)**
```java
// CURRENT: Lines 13-22
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Request model for signing a credential message")
public class SignCredentialRequestDto {
    @ApiModelProperty(notes = "The message to be signed")
    private String message;

    @ApiModelProperty(notes = "Application ID for key selection")
    private String applicationId;

    @ApiModelProperty(notes = "Reference ID for key selection")
    private String referenceId;
}
```

**ENHANCE: Add validation annotations:**
```java
// ADD: Import statements
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

// ENHANCE: Add validation annotations
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Request model for signing a credential message")
public class SignCredentialRequestDto {
    @NotBlank(message = "Message cannot be null or empty")
    @Size(max = 1048576, message = "Message size cannot exceed 1MB")
    @ApiModelProperty(notes = "The message to be signed (Base64 encoded, max 1MB)")
    private String message;

    @NotBlank(message = "ApplicationId cannot be null or empty")
    @Pattern(regexp = "^[A-Za-z0-9_-]{1,50}$", message = "Invalid ApplicationId format")
    @ApiModelProperty(notes = "Application ID for key selection (alphanumeric, max 50 chars)")
    private String applicationId;

    @NotBlank(message = "ReferenceId cannot be null or empty")
    @Pattern(regexp = "^[A-Za-z0-9_-]{1,50}$", message = "Invalid ReferenceId format")
    @ApiModelProperty(notes = "Reference ID for key selection (alphanumeric, max 50 chars)")
    private String referenceId;
}
```

### **4. Utility Class Enhancement**
**File:** `kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/signature/util/SignatureUtil.java`

#### **🆕 ADD: New Validation Methods (After Line 105)**
```java
// ADD: New validation methods after existing methods
public static boolean isValidBase64(String base64String) {
    if (base64String == null || base64String.isEmpty()) {
        return false;
    }
    
    // Check if string matches Base64 pattern
    Pattern base64Pattern = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");
    if (!base64Pattern.matcher(base64String).matches()) {
        return false;
    }
    
    // Check if length is multiple of 4
    if (base64String.length() % 4 != 0) {
        return false;
    }
    
    // Try to decode to verify it's valid Base64
    try {
        Base64.decodeBase64(base64String);
        return true;
    } catch (Exception e) {
        return false;
    }
}

public static boolean isValidApplicationId(String applicationId) {
    if (applicationId == null || applicationId.isEmpty()) {
        return false;
    }
    return applicationId.matches("^[A-Za-z0-9_-]{1,50}$");
}

public static boolean isValidReferenceId(String referenceId) {
    if (referenceId == null || referenceId.isEmpty()) {
        return false;
    }
    return referenceId.matches("^[A-Za-z0-9_-]{1,50}$");
}
```

### **5. Constants Enhancement**
**File:** `kernel/kernel-keymanager-service/src/main/java/io/mosip/kernel/signature/constant/SignatureConstant.java`

#### **🆕 ADD: Security Constants**
```java
// ADD: Security-related constants
public static final int MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB limit
public static final int MIN_DER_SIZE = 8; // Minimum DER signature size
public static final int MAX_DER_SIZE = 72; // Maximum DER signature size for P-256
public static final int P256_RAW_SIGNATURE_SIZE = 64; // 32 * 2 for P-256
```

## 📋 **Summary of Required Changes**

### **Files to Modify:**
1. ✅ **SignatureServiceImpl.java** - Main security fixes (Lines 1742-1781)
2. ✅ **SignatureController.java** - Enhanced logging (Lines 349-358)
3. ✅ **SignCredentialRequestDto.java** - Validation annotations (Lines 13-22)
4. ✅ **SignatureUtil.java** - New validation methods (After Line 105)
5. ✅ **SignatureConstant.java** - Security constants

### **Critical Changes by Priority:**

#### **🔴 CRITICAL (Must Fix Immediately):**
1. **Line 1747**: Add certificate validation
2. **Lines 1752-1755**: Fix information disclosure in logs
3. **Line 1743-1745**: Add input validation

#### **🟡 HIGH (Important Security Fixes):**
4. **Line 1758**: Add access control validation
5. **Line 1771**: Add bounds checking for signature conversion
6. **Lines 1777-1780**: Enhance error handling

#### **🟢 MEDIUM (Enhancement):**
7. **Controller**: Add comprehensive logging
8. **DTO**: Add validation annotations
9. **Utility**: Add validation methods
10. **Constants**: Add security constants

### **Implementation Order:**
1. **First**: Fix critical certificate validation (Line 1747)
2. **Second**: Add input validation (Lines 1743-1745)
3. **Third**: Fix logging issues (Lines 1752-1755)
4. **Fourth**: Add access control (Line 1758)
5. **Fifth**: Enhance error handling (Lines 1777-1780)
6. **Sixth**: Add supporting methods and constants

This systematic approach ensures the most critical security vulnerabilities are addressed first while maintaining system stability.
