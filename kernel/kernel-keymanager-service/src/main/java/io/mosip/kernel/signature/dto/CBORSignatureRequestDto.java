package io.mosip.kernel.signature.dto;

public class CBORSignatureRequestDto {
    private String dataToSign;
    private String applicationId;
    private String referenceId;

    public String getDataToSign() { return dataToSign; }
    public void setDataToSign(String dataToSign) { this.dataToSign = dataToSign; }
    public String getApplicationId() { return applicationId; }
    public void setApplicationId(String applicationId) { this.applicationId = applicationId; }
    public String getReferenceId() { return referenceId; }

    public void setReferenceId(String referenceId) { this.referenceId = referenceId; }
} 