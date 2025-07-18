package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@ApiModel("SignBinaryResponseDto")
public class SignBinaryResponseDto {
    @ApiModelProperty("Base64-encoded signature")
    private String signatureBase64;

    @ApiModelProperty("UTC timestamp")
    private String timestamp;
} 