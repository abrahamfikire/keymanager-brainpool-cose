package io.mosip.kernel.signature.dto;

public class COSESign1ResponseDto {
    private String coseSign1Data; // Base64 encoded COSE_Sign1
    private String timestamp;

    public String getCoseSign1Data() { return coseSign1Data; }
    public void setCoseSign1Data(String coseSign1Data) { this.coseSign1Data = coseSign1Data; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
} 