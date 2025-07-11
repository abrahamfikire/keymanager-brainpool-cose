package io.mosip.kernel.signature.dto;

public class COSESign1VerifyResponseDto {
    private boolean signatureValid;
    private String message;
    private boolean trustValid;

    public boolean isSignatureValid() { return signatureValid; }
    public void setSignatureValid(boolean signatureValid) { this.signatureValid = signatureValid; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public boolean isTrustValid() { return trustValid; }
    public void setTrustValid(boolean trustValid) { this.trustValid = trustValid; }
} 