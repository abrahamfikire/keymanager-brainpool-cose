// Example: SignatureService.java
public byte[] signCredential(byte[] credential, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(credential);
    return signature.sign();
}# QR Code Authenticator Offline Implementation Plan

## Overview
This document outlines the implementation plan for creating an offline QR code authenticator system that allows mobile apps to verify QR codes without requiring internet connectivity.

## Current Status ✅

### Completed Features:
1. **JWKS Endpoint Enabled** - `/keymanager/jwks` endpoint is now active
2. **QR Code Generation Endpoint** - `/signature/generateQRCode` endpoint created
3. **DTOs Created** - QRCodeRequestDto and QRCodeResponseDto implemented
4. **Service Implementation** - generateQRCode method added to SignatureServiceImpl

## Implementation Phases

### Phase 1: Core Infrastructure ✅ (COMPLETED)
- [x] Enable JWKS endpoint for public key distribution
- [x] Create QR code generation endpoint
- [x] Implement DTOs for QR code requests/responses
- [x] Add service method for QR code generation

### Phase 2: QR Code Generation Enhancement 🔄 (IN PROGRESS)
- [ ] Add QR code image generation library (ZXing/QRGen)
- [ ] Implement QR code image generation
- [ ] Add QR code format validation
- [ ] Implement QR code size optimization

### Phase 3: Mobile App Integration 📱 (PLANNED)
- [ ] Create mobile app SDK for QR code verification
- [ ] Implement offline JWKS caching
- [ ] Add QR code scanning functionality
- [ ] Implement signature verification on mobile

### Phase 4: Advanced Features 🚀 (FUTURE)
- [ ] Add QR code expiry validation
- [ ] Implement QR code revocation
- [ ] Add multi-format QR code support
- [ ] Implement QR code analytics

## Technical Architecture

### QR Code Data Structure
```json
{
  "payload": {
    "type": "CREDENTIAL|IDENTITY|CERTIFICATE",
    "data": "base64_encoded_data",
    "issuerId": "www.mosip.io",
    "timestamp": "2025-07-31T11:00:00Z",
    "keyId": "base64_key_id",
    "algorithm": "ES256",
    "additionalInfo": "optional_additional_data",
    "expiryTime": "2025-08-31T11:00:00Z"
  },
  "signature": "base64_encoded_signature",
  "jwksUrl": "/keymanager/jwks?applicationId=APP_ID&referenceId=REF_ID"
}
```

### API Endpoints

#### 1. QR Code Generation
```
POST /signature/generateQRCode
Content-Type: application/json

{
  "applicationId": "KERNEL",
  "referenceId": "SIGN",
  "dataToSign": "base64_encoded_data",
  "qrCodeType": "CREDENTIAL",
  "additionalInfo": "optional_data",
  "expiryTime": "2025-08-31T11:00:00Z",
  "issuerId": "www.mosip.io"
}
```

#### 2. JWKS Endpoint (for offline verification)
```
GET /keymanager/jwks?applicationId=KERNEL&referenceId=SIGN
Content-Type: application/json

{
  "keys": [
    {
      "alg": "ES256",
      "crv": "P-256",
      "kid": "key_id",
      "kty": "EC",
      "x": "base64url_x_coordinate",
      "y": "base64url_y_coordinate",
      "x5c": ["base64_certificate"]
    }
  ]
}
```

## Mobile App Integration Guide

### 1. QR Code Scanning
```javascript
// Example mobile app code
const qrCodeData = scanQRCode();
const qrData = JSON.parse(qrCodeData);

// Extract components
const payload = qrData.payload;
const signature = qrData.signature;
const jwksUrl = qrData.jwksUrl;
```

### 2. Offline Verification
```javascript
// Verify signature using cached JWKS
const publicKey = getPublicKeyFromJWKS(qrData.payload.keyId);
const isValid = verifySignature(payload, signature, publicKey);
```

### 3. JWKS Caching Strategy
- Cache JWKS data locally on mobile app
- Implement cache expiry (e.g., 24 hours)
- Fetch fresh JWKS when cache expires
- Handle offline scenarios gracefully

## Security Considerations

### 1. Signature Verification
- Use ES256 (ECDSA with SHA-256) for signatures
- Verify signature using public key from JWKS
- Validate key ID matches expected key

### 2. QR Code Security
- Implement QR code expiry validation
- Add issuer validation
- Implement QR code revocation mechanism

### 3. Offline Security
- Cache JWKS securely on mobile device
- Implement certificate pinning
- Add integrity checks for cached data

## Dependencies to Add

### QR Code Generation
```xml
<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>core</artifactId>
    <version>3.5.1</version>
</dependency>
<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>javase</artifactId>
    <version>3.5.1</version>
</dependency>
```

### Mobile App Dependencies
```javascript
// React Native
npm install react-native-qrcode-scanner
npm install react-native-camera

// Flutter
dependencies:
  qr_code_scanner: ^1.0.1
  crypto: ^3.0.3
```

## Testing Strategy

### 1. Unit Tests
- QR code generation tests
- Signature verification tests
- JWKS endpoint tests

### 2. Integration Tests
- End-to-end QR code generation and verification
- Mobile app integration tests
- Offline verification tests

### 3. Security Tests
- Signature tampering tests
- Expired QR code tests
- Invalid key tests

## Deployment Considerations

### 1. Server Configuration
- Enable CORS for mobile app access
- Configure rate limiting for JWKS endpoint
- Implement caching for JWKS responses

### 2. Mobile App Deployment
- Implement QR code scanning permissions
- Add offline mode handling
- Configure certificate pinning

### 3. Monitoring
- Monitor QR code generation metrics
- Track JWKS endpoint usage
- Monitor mobile app verification success rates

## Next Steps

1. **Add QR Code Image Generation** - Implement actual QR code image generation using ZXing
2. **Create Mobile App SDK** - Develop a reusable SDK for mobile apps
3. **Implement Offline Verification** - Add offline signature verification capabilities
4. **Add Security Features** - Implement QR code expiry and revocation
5. **Performance Optimization** - Optimize QR code size and verification speed

## Success Metrics

- QR code generation time < 500ms
- Mobile app verification time < 200ms
- JWKS endpoint response time < 100ms
- 99.9% uptime for JWKS endpoint
- Zero security vulnerabilities in QR code verification 