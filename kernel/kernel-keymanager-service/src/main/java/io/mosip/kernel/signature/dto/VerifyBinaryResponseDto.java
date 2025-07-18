package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@ApiModel("VerifyBinaryResponseDto")
public class VerifyBinaryResponseDto {
    @ApiModelProperty("Is the signature valid?")
    private boolean valid;

    @ApiModelProperty("Validation message")
    private String message;

    @ApiModelProperty("UTC timestamp")
    private String timestamp;
} 