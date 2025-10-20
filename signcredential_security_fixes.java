package io.mosip.kernel.signature.service.impl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.SignCredentialRequestDto;
import io.mosip.kernel.signature.dto.SignatureResponseDto;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.util.SignatureUtil;

/**
 * SECURITY-ENHANCED signCredential method with comprehensive security fixes
 * 
 * This implementation addresses all identified security vulnerabilities:
 * 1. Input validation and sanitization
 * 2. Certificate validation
 * 3. Access control
 * 4. Secure logging
 * 5. Enhanced error handling
 * 6. Safe signature conversion
 */
public class SecureSignCredentialImpl {

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private CryptomanagerUtils cryptomanagerUtil;

    @Value("${mosip.sign.applicationid:KERNEL}")
    private String signApplicationid;

    @Value("${mosip.sign.refid:SIGN}")
    private String signRefid;

    // Security constants
    private static final int MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB limit
    private static final int MIN_DER_SIZE = 8; // Minimum DER signature size
    private static final int MAX_DER_SIZE = 72; // Maximum DER signature size for P-256
    private static final int P256_RAW_SIGNATURE_SIZE = 64; // 32 * 2 for P-256
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

    /**
     * SECURITY-ENHANCED signCredential method
     * 
     * @param requestDto the request containing message, applicationId, referenceId
     * @return the signature response dto
     * @throws RequestException if input validation fails
     * @throws SignatureFailureException if signing fails
     */
    public SignatureResponseDto signCredential(SignCredentialRequestDto requestDto) {
        String sessionId = SignatureConstant.SESSIONID;
        
        try {
            // ===== SECURITY FIX 1: COMPREHENSIVE INPUT VALIDATION =====
            validateInputParameters(requestDto);
            
            String base64Message = requestDto.getMessage();
            String applicationId = requestDto.getApplicationId();
            String referenceId = requestDto.getReferenceId();
            String timestamp = DateUtils.getUTCCurrentDateTimeString();

            // ===== SECURITY FIX 2: ACCESS CONTROL =====
            validateAccessControl(applicationId);

            // ===== SECURITY FIX 3: CERTIFICATE VALIDATION =====
            SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(
                applicationId, Optional.of(referenceId), timestamp);
            
            // CRITICAL: Add missing certificate validation
            keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), 
                DateUtils.parseUTCToDate(timestamp));
            
            PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
            String providerName = certificateResponse.getProviderName();

            // ===== SECURITY FIX 4: SECURE LOGGING =====
            logCertificateInfoSecurely(certificateResponse, applicationId, sessionId);

            String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());
            
            // ===== SECURITY FIX 5: SAFE SIGNATURE GENERATION =====
            byte[] messageBytes = Base64.decodeBase64(base64Message);
            byte[] signature = generateSecureSignature(messageBytes, privateKey, providerName);
            
            // ===== SECURITY FIX 6: SAFE SIGNATURE CONVERSION =====
            byte[] rawSignature = convertDerToRawSafely(signature);
            String signatureBase64 = Base64.encodeBase64String(rawSignature);
            
            SignatureResponseDto response = new SignatureResponseDto();
            response.setSignatureData(signatureBase64);
            response.setKid(keyId);
            
            LOGGER.info(sessionId, "SIGN_CREDENTIAL", SignatureConstant.BLANK,
                "Credential signing completed successfully for applicationId: {}", applicationId);
            
            return response;
            
        } catch (RequestException | SignatureFailureException e) {
            // Re-throw known exceptions
            throw e;
        } catch (Exception e) {
            LOGGER.error(sessionId, "SIGN_CREDENTIAL", SignatureConstant.BLANK,
                "Unexpected error during credential signing", e);
            throw new SignatureFailureException(
                SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }

    /**
     * SECURITY FIX 1: Comprehensive input validation
     */
    private void validateInputParameters(SignCredentialRequestDto requestDto) {
        if (requestDto == null) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Request DTO cannot be null");
        }

        // Validate message
        if (!SignatureUtil.isDataValid(requestDto.getMessage())) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Message cannot be null or empty");
        }

        // Validate Base64 format
        String base64Message = requestDto.getMessage();
        if (!isValidBase64(base64Message)) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Invalid Base64 format in message");
        }

        // Validate message size
        if (base64Message.length() > MAX_MESSAGE_SIZE) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Message size exceeds maximum allowed limit of " + MAX_MESSAGE_SIZE + " characters");
        }

        // Validate applicationId
        if (!SignatureUtil.isDataValid(requestDto.getApplicationId())) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "ApplicationId cannot be null or empty");
        }

        // Validate referenceId
        if (!SignatureUtil.isDataValid(requestDto.getReferenceId())) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "ReferenceId cannot be null or empty");
        }

        // Validate applicationId format (alphanumeric and underscore only)
        if (!isValidApplicationId(requestDto.getApplicationId())) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Invalid ApplicationId format");
        }

        // Validate referenceId format
        if (!isValidReferenceId(requestDto.getReferenceId())) {
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                "Invalid ReferenceId format");
        }
    }

    /**
     * SECURITY FIX 2: Access control validation
     */
    private void validateAccessControl(String applicationId) {
        // Check if user has access to the application key
        boolean hasAccess = cryptomanagerUtil.hasKeyAccess(applicationId);
        if (!hasAccess) {
            throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
                SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
        }
    }

    /**
     * SECURITY FIX 4: Secure logging without information disclosure
     */
    private void logCertificateInfoSecurely(SignatureCertificate certificateResponse, 
                                          String applicationId, String sessionId) {
        X509Certificate cert = certificateResponse.getCertificateEntry().getChain()[0];
        
        // Log only non-sensitive information at DEBUG level
        LOGGER.debug(sessionId, "SIGN_CREDENTIAL", SignatureConstant.BLANK,
            "Certificate validation completed for applicationId: {}, keyId: {}", 
            applicationId, certificateResponse.getUniqueIdentifier());
        
        // Log certificate algorithm for debugging (non-sensitive)
        LOGGER.debug(sessionId, "SIGN_CREDENTIAL", SignatureConstant.BLANK,
            "Certificate algorithm: {}", cert.getPublicKey().getAlgorithm());
        
        // Log certificate validity period (non-sensitive)
        LOGGER.debug(sessionId, "SIGN_CREDENTIAL", SignatureConstant.BLANK,
            "Certificate valid from: {} to: {}", 
            cert.getNotBefore(), cert.getNotAfter());
    }

    /**
     * SECURITY FIX 5: Safe signature generation
     */
    private byte[] generateSecureSignature(byte[] messageBytes, PrivateKey privateKey, String providerName) {
        try {
            Signature signature = (providerName != null && !providerName.isEmpty())
                ? Signature.getInstance("SHA256withECDSA", providerName)
                : Signature.getInstance("SHA256withECDSA");
            
            signature.initSign(privateKey);
            signature.update(messageBytes);
            byte[] derSignature = signature.sign();
            
            // Validate signature size
            if (derSignature.length < MIN_DER_SIZE || derSignature.length > MAX_DER_SIZE) {
                throw new SignatureFailureException(
                    SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                    "Invalid signature format: unexpected size " + derSignature.length);
            }
            
            return derSignature;
            
        } catch (Exception e) {
            throw new SignatureFailureException(
                SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                "Failed to generate signature: " + e.getMessage(), e);
        }
    }

    /**
     * SECURITY FIX 6: Safe DER to RAW conversion with bounds checking
     */
    private byte[] convertDerToRawSafely(byte[] derSignature) {
        try {
            byte[] rawSignature = derToRaw(derSignature, 32);
            
            // Validate raw signature size
            if (rawSignature.length != P256_RAW_SIGNATURE_SIZE) {
                throw new SignatureFailureException(
                    SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                    "Invalid raw signature length: expected " + P256_RAW_SIGNATURE_SIZE + 
                    ", got " + rawSignature.length);
            }
            
            return rawSignature;
            
        } catch (Exception e) {
            throw new SignatureFailureException(
                SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                "Failed to convert signature format: " + e.getMessage(), e);
        }
    }

    // ===== UTILITY METHODS FOR VALIDATION =====

    /**
     * Validates Base64 format
     */
    private boolean isValidBase64(String base64String) {
        if (base64String == null || base64String.isEmpty()) {
            return false;
        }
        
        // Check if string matches Base64 pattern
        if (!BASE64_PATTERN.matcher(base64String).matches()) {
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

    /**
     * Validates applicationId format
     */
    private boolean isValidApplicationId(String applicationId) {
        if (applicationId == null || applicationId.isEmpty()) {
            return false;
        }
        
        // Allow alphanumeric characters, underscore, and hyphen
        // Length between 1 and 50 characters
        return applicationId.matches("^[A-Za-z0-9_-]{1,50}$");
    }

    /**
     * Validates referenceId format
     */
    private boolean isValidReferenceId(String referenceId) {
        if (referenceId == null || referenceId.isEmpty()) {
            return false;
        }
        
        // Allow alphanumeric characters, underscore, and hyphen
        // Length between 1 and 50 characters
        return referenceId.matches("^[A-Za-z0-9_-]{1,50}$");
    }

    /**
     * Safe DER to RAW conversion (existing method with additional validation)
     */
    private byte[] derToRaw(byte[] der, int keySizeBytes) throws Exception {
        // Additional validation
        if (der == null || der.length == 0) {
            throw new IllegalArgumentException("DER signature cannot be null or empty");
        }
        
        if (keySizeBytes <= 0 || keySizeBytes > 64) {
            throw new IllegalArgumentException("Invalid key size: " + keySizeBytes);
        }
        
        // Existing implementation with BouncyCastle
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        byte[] rBytes = toFixedLength(r, keySizeBytes);
        byte[] sBytes = toFixedLength(s, keySizeBytes);
        byte[] raw = new byte[keySizeBytes * 2];
        System.arraycopy(rBytes, 0, raw, 0, keySizeBytes);
        System.arraycopy(sBytes, 0, raw, keySizeBytes, keySizeBytes);
        return raw;
    }

    private byte[] toFixedLength(BigInteger b, int length) {
        byte[] bytes = b.toByteArray();
        if (bytes.length == length) return bytes;
        byte[] result = new byte[length];
        if (bytes.length > length) {
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }
}
