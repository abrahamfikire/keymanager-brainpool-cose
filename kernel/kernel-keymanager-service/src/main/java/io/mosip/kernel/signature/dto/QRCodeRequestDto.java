package io.mosip.kernel.signature.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * DTO for QR code generation request
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class QRCodeRequestDto {
    
    @NotBlank(message = "Application ID is required")
    private String applicationId;
    
    @NotBlank(message = "Reference ID is required")
    private String referenceId;
    
    @NotBlank(message = "Data to sign is required")
    private String dataToSign;
    
    @NotBlank(message = "QR code type is required")
    private String qrCodeType; // "CREDENTIAL", "IDENTITY", "CERTIFICATE"
    
    private String additionalInfo; // Optional additional information
    
    private String expiryTime; // Optional expiry time for the QR code
    
    private String issuerId; // Optional issuer identifier
} 