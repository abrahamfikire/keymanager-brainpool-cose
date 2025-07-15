package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Request model for verifying a credential signature")
public class VerifyCredentialRequestDto {
    @ApiModelProperty(notes = "The original message that was signed")
    private String message;

    @ApiModelProperty(notes = "The base64-encoded signature to verify")
    private String signature;

    @ApiModelProperty(notes = "Application ID for key selection")
    private String applicationId;

    @ApiModelProperty(notes = "Reference ID for key selection")
    private String referenceId;
} 