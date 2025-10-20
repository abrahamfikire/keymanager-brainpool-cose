package io.mosip.kernel.signature.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * DTO for QR code generation response
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class QRCodeResponseDto {
    
    private String qrCodeData; // Base64 encoded QR code image
    
    private String qrCodeText; // Raw QR code text content
    
    private String signature; // Base64 encoded signature
    
    private String keyId; // Key identifier for verification
    
    private String algorithm; // Signature algorithm used
    
    private String issuerId; // Issuer identifier
    
    private String expiryTime; // Expiry time of the QR code
    
    private String verificationUrl; // URL for online verification (optional)
    
    private String jwksUrl; // JWKS endpoint URL for offline verification
    
    private String timestamp; // Generation timestamp
} 