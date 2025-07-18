package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@ApiModel("SignBinaryRequestDto")
public class SignBinaryRequestDto {
    @ApiModelProperty("Base64-encoded binary data to sign")
    private String dataBase64;

    @ApiModelProperty("Application ID")
    private String applicationId;

    @ApiModelProperty("Reference ID")
    private String referenceId;
} 