package io.mosip.kernel.signature.dto;

public class COSESign1RequestDto {
    private String dataToSign; // Base64 encoded JSON
    private String applicationId;
    private String referenceId;
    private boolean includeCertificate;
    private boolean includeCertHash;
    private String certificateUrl;

    // Getters and setters
    public String getDataToSign() { return dataToSign; }
    public void setDataToSign(String dataToSign) { this.dataToSign = dataToSign; }
    public String getApplicationId() { return applicationId; }
    public void setApplicationId(String applicationId) { this.applicationId = applicationId; }
    public String getReferenceId() { return referenceId; }
    public void setReferenceId(String referenceId) { this.referenceId = referenceId; }
    public boolean isIncludeCertificate() { return includeCertificate; }
    public void setIncludeCertificate(boolean includeCertificate) { this.includeCertificate = includeCertificate; }
    public boolean isIncludeCertHash() { return includeCertHash; }
    public void setIncludeCertHash(boolean includeCertHash) { this.includeCertHash = includeCertHash; }
    public String getCertificateUrl() { return certificateUrl; }
    public void setCertificateUrl(String certificateUrl) { this.certificateUrl = certificateUrl; }
} 