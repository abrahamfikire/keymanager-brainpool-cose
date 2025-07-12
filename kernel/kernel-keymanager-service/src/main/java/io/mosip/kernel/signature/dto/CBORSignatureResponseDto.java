package io.mosip.kernel.signature.dto;

public class CBORSignatureResponseDto {
    private String cborSignedData;
    private String timestamp;

    public String getCborSignedData() { return cborSignedData; }
    public void setCborSignedData(String cborSignedData) { this.cborSignedData = cborSignedData; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
} 