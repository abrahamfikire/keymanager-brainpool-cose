package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@ApiModel("VerifyBinaryRequestDto")
public class VerifyBinaryRequestDto {
    @ApiModelProperty("Base64-encoded binary data that was signed")
    private String dataBase64;

    @ApiModelProperty("Base64-encoded signature to verify")
    private String signatureBase64;

    @ApiModelProperty("Application ID")
    private String applicationId;

    @ApiModelProperty("Reference ID")
    private String referenceId;
} 