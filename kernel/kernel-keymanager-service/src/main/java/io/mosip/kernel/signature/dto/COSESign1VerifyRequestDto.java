package io.mosip.kernel.signature.dto;

public class COSESign1VerifyRequestDto {
    private String coseSign1Data; // Base64 encoded COSE_Sign1
    private String actualData; // Base64 encoded JSON
    private String applicationId;
    private String referenceId;
    private String certificateData; // Optional, PEM/Base64

    public String getCoseSign1Data() { return coseSign1Data; }
    public void setCoseSign1Data(String coseSign1Data) { this.coseSign1Data = coseSign1Data; }
    public String getActualData() { return actualData; }
    public void setActualData(String actualData) { this.actualData = actualData; }
    public String getApplicationId() { return applicationId; }
    public void setApplicationId(String applicationId) { this.applicationId = applicationId; }
    public String getReferenceId() { return referenceId; }
    public void setReferenceId(String referenceId) { this.referenceId = referenceId; }
    public String getCertificateData() { return certificateData; }
    public void setCertificateData(String certificateData) { this.certificateData = certificateData; }
} 