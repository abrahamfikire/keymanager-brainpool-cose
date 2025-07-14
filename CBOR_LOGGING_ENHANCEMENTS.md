    # CBOR Signing Enhanced Logging

This document describes the enhanced logging features added to the CBOR signing functionality to help debug and troubleshoot CBOR-related errors.

## Overview

The enhanced logging provides comprehensive debugging information for CBOR signing operations, including:

- **Request validation logging**
- **Input data analysis**
- **CBOR structure parsing details**
- **Error-specific logging with byte analysis**
- **Performance metrics**

## Logging Levels

### INFO Level
- Request start/completion
- Success/failure status
- Input/output data lengths
- Certificate and key information

### DEBUG Level
- Detailed CBOR parsing steps
- Certificate validation details
- Signature creation process
- Data transformation steps

### WARN Level
- Invalid application IDs (with fallback)
- Odd-length hex strings
- Null or empty input data

### ERROR Level
- Specific CBOR decoding errors
- UTF-8 malformation details
- Hex decoding failures
- Certificate validation errors

## Key Logging Features

### 1. Input Validation Logging

```java
// Validates hex string length
if (cborSignRequestDto.getDataToSign().length() % 2 != 0) {
    LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
            "Invalid hex string: odd number of characters. Length: {}", 
            cborSignRequestDto.getDataToSign().length());
    throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
            "Invalid hex string: odd number of characters");
}
```

### 2. CBOR Error Analysis

```java
// Specific handling for CBOR UTF-8 errors
catch (CBORMalformedUtf8Exception e) {
    LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
            "CBOR UTF-8 error at offset {}: {}. This indicates binary data was encoded as text string.", 
            e.getOffset(), e.getMessage());
    LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
            "Problematic bytes around offset {}: {}", e.getOffset(), 
            getHexBytesAroundOffset(claim169Bytes, e.getOffset()));
    throw e;
}
```

### 3. Byte Analysis Helper

```java
/**
 * Helper method to get hex representation of bytes around a specific offset
 * for debugging CBOR errors
 */
private String getHexBytesAroundOffset(byte[] data, int offset) {
    int start = Math.max(0, offset - 10);
    int end = Math.min(data.length, offset + 10);
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < end; i++) {
        if (i == offset) {
            sb.append(">>>");
        }
        sb.append(String.format("%02x ", data[i]));
        if (i == offset) {
            sb.append("<<< ");
        }
    }
    return sb.toString();
}
```

## Log Entry Examples

### Successful CBOR Signing
```
INFO  - CBOR_SIGN_CONTROLLER - Received CBOR signing request. RequestId: test-valid-cbor, ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign length: 140 characters
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign preview: a3041a499602d2...6e6465726c616e64
INFO  - CBOR_SIGN - Starting CBOR signing process. ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN - Input dataToSign length: 140 characters
DEBUG - CBOR_SIGN_INTERNAL - Processing CBOR signing with applicationId: ID_REPO, referenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_INTERNAL - Getting signature certificate for applicationId: ID_REPO, referenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_INTERNAL - Certificate validation successful. KeyId: c4c2b5ca-aaec-4cba-976b-96e4e8adb1db
DEBUG - CBOR_SIGN_INTERNAL - Using algorithm: -7, keyId: c4c2b5ca-aaec-4cba-976b-96e4e8adb1db
DEBUG - CBOR_SIGN_INTERNAL - Decoding hex string to bytes. Input length: 140
DEBUG - CBOR_SIGN_INTERNAL - Hex decoding successful. Decoded bytes length: 70
DEBUG - CBOR_SIGN_INTERNAL - Starting CBOR decoding of claim169 data
DEBUG - CBOR_SIGN_INTERNAL - CBOR decoding successful. Item type: CBORPairList
DEBUG - CBOR_SIGN_INTERNAL - CBOR map parsed successfully. Map size: 3
DEBUG - CBOR_SIGN_INTERNAL - Creating updated CBOR structure
DEBUG - CBOR_SIGN_INTERNAL - Updated CBOR structure encoded. Size: 70 bytes
DEBUG - CBOR_SIGN_INTERNAL - CWT claims set created. Issuer: www.mosip.io, Expiry: 1735689600
DEBUG - CBOR_SIGN_INTERNAL - Signature structure created. Starting signing process
DEBUG - CBOR_SIGN_INTERNAL - Signature created. Signature length: 64 bytes
DEBUG - CBOR_SIGN_INTERNAL - CBOR signing completed. Final hex length: 1024
INFO  - CBOR_SIGN - CBOR signing completed successfully. Output length: 1024 characters
INFO  - CBOR_SIGN_CONTROLLER - CBOR signing completed successfully. Output length: 1024 characters
```

### CBOR UTF-8 Error
```
INFO  - CBOR_SIGN_CONTROLLER - Received CBOR signing request. RequestId: test-invalid-cbor, ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign length: 1762 characters
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign preview: a3041a66b1e3b5...edf6180000
INFO  - CBOR_SIGN - Starting CBOR signing process. ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN - Input dataToSign length: 1762 characters
DEBUG - CBOR_SIGN_INTERNAL - Processing CBOR signing with applicationId: ID_REPO, referenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_INTERNAL - Getting signature certificate for applicationId: ID_REPO, referenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_INTERNAL - Certificate validation successful. KeyId: c4c2b5ca-aaec-4cba-976b-96e4e8adb1db
DEBUG - CBOR_SIGN_INTERNAL - Using algorithm: -7, keyId: c4c2b5ca-aaec-4cba-976b-96e4e8adb1db
DEBUG - CBOR_SIGN_INTERNAL - Decoding hex string to bytes. Input length: 1762
DEBUG - CBOR_SIGN_INTERNAL - Hex decoding successful. Decoded bytes length: 881
DEBUG - CBOR_SIGN_INTERNAL - Starting CBOR decoding of claim169 data
ERROR - CBOR_SIGN_INTERNAL - CBOR UTF-8 error at offset 50: Malformed UTF-8 byte sequence: major=3, info=24, offset=50, cause=Input length = 1. This indicates binary data was encoded as text string.
ERROR - CBOR_SIGN_INTERNAL - Problematic bytes around offset 50: 37 38 39 30 61 62 a9 04 78 68 >>>4a 61 6e 65 20 44 6f 65 08 78 08 <<< 
ERROR - CBOR_SIGN - CBOR UTF-8 error at offset 50: Malformed UTF-8 byte sequence: major=3, info=24, offset=50, cause=Input length = 1. This indicates binary data was encoded as text string.
ERROR - CBOR_SIGN - Problematic bytes around offset 50: 37 38 39 30 61 62 a9 04 78 68 >>>4a 61 6e 65 20 44 6f 65 08 78 08 <<< 
WARN  - CBOR_SIGN_CONTROLLER - CBOR signing completed but output is null
```

### Odd-Length Hex String
```
INFO  - CBOR_SIGN_CONTROLLER - Received CBOR signing request. RequestId: test-odd-length-hex, ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign length: 139 characters
DEBUG - CBOR_SIGN_CONTROLLER - Input dataToSign preview: a3041a499602d2...6e6465726c616e6
WARN  - CBOR_SIGN_CONTROLLER - Input hex string has odd number of characters: 139
INFO  - CBOR_SIGN - Starting CBOR signing process. ApplicationId: ID_REPO, ReferenceId: EC_SECP256R1_SIGN
DEBUG - CBOR_SIGN - Input dataToSign length: 139 characters
ERROR - CBOR_SIGN - Invalid hex string: odd number of characters. Length: 139
WARN  - CBOR_SIGN_CONTROLLER - CBOR signing completed but output is null
```

## Testing the Enhanced Logging

Use the provided test script to verify the logging functionality:

```bash
python3 test_cbor_logging.py
```

This script tests various scenarios:
- Valid CBOR data
- Invalid CBOR data (with UTF-8 errors)
- Odd-length hex strings
- Null input data

## Configuration

### Log Level Configuration

To enable detailed debugging, set the log level to DEBUG in your application.properties:

```properties
# Enable DEBUG logging for CBOR operations
logging.level.io.mosip.kernel.signature=DEBUG
logging.level.io.mosip.kernel.signature.service.impl.SignatureServiceImpl=DEBUG
logging.level.io.mosip.kernel.signature.controller.SignatureController=DEBUG
```

### Log Format

The logging uses the MOSIP standard format with session ID, operation type, and detailed messages:

```
{timestamp} - {sessionId} - {operation} - {message}
```

## Troubleshooting Guide

### Common Issues and Log Messages

1. **CBORMalformedUtf8Exception**
   - **Cause**: Binary data encoded as text string
   - **Solution**: Ensure photo data is encoded as byte strings, not text strings
   - **Log**: Look for "CBOR UTF-8 error at offset" with byte analysis

2. **Odd-Length Hex String**
   - **Cause**: Hex string has odd number of characters
   - **Solution**: Ensure hex string has even number of characters
   - **Log**: Look for "Invalid hex string: odd number of characters"

3. **CBORInsufficientDataException**
   - **Cause**: Input data is truncated
   - **Solution**: Ensure complete hex string is sent
   - **Log**: Look for "CBOR insufficient data: Input may be truncated"

4. **DecoderException**
   - **Cause**: Invalid hex characters in input
   - **Solution**: Validate hex string format
   - **Log**: Look for "Failed to decode hex string"

## Benefits

1. **Faster Debugging**: Specific error messages with byte-level analysis
2. **Better Error Handling**: Different exception types with appropriate responses
3. **Input Validation**: Early detection of common issues
4. **Performance Monitoring**: Detailed timing and size information
5. **Security**: Logs don't expose sensitive data while providing debugging info

## Best Practices

1. **Monitor Logs**: Regularly check for CBOR-related errors
2. **Validate Input**: Ensure hex strings are properly formatted before sending
3. **Use Valid CBOR**: Generate CBOR data using proper tools
4. **Handle Errors**: Implement proper error handling based on log messages
5. **Performance**: Monitor log volume and adjust log levels as needed 

---

## 1. **Install the Required Library**

You’ll need the `cbor2` library. Install it with:

```bash
pip install cbor2
```

---

## 2. **Python Code Example**

Suppose your input is a Python list/dict (parsed from JSON):

```python
import json
import cbor2

# Your JSON-like input as a string
json_input = '''
[
  { "1": -7 },
  { "4": "4" },
  {
    "4": 1924992000,
    "7": "5d57468f-1a97-40d3-b2d9-65796feaca43",
    "169": {
      "4": "Mikias Estifanos Paulos",
      "8": "19971007",
      "9": 1,
      "12": "09239979918",
      "13": "Ethiopia",
      "62": [
        { "0": "52494646...", "1": 0 },
        { "0": "3d8a7e81...", "1": 1 }
      ]
    }
  },
  "f38d9144..."
]
'''

# Parse JSON string to Python object
data = json.loads(json_input)

# Convert to CBOR bytes
cbor_bytes = cbor2.dumps(data)

# Save to file (optional)
with open('output.cbor', 'wb') as f:
    f.write(cbor_bytes)

# Print as hex for inspection
print(cbor_bytes.hex())
```

---

## 3. **How to Use**

- Replace `json_input` with your actual JSON string.
- The variable `cbor_bytes` now contains the CBOR-encoded bytes, ready for signing or further processing.

---

**Let me know if you want to handle files, or if you have a specific input format!** 