package io.mosip.kernel.signature.dto;

public class CBORSignatureVerifyRequestDto {
    private String cborSignatureData;
    private String applicationId;
    private String referenceId;

    public String getCborSignatureData() { return cborSignatureData; }
    public void setCborSignatureData(String cborSignatureData) { this.cborSignatureData = cborSignatureData; }
    public String getApplicationId() { return applicationId; }
    public void setApplicationId(String applicationId) { this.applicationId = applicationId; }
    public String getReferenceId() { return referenceId; }
    public void setReferenceId(String referenceId) { this.referenceId = referenceId; }
} 