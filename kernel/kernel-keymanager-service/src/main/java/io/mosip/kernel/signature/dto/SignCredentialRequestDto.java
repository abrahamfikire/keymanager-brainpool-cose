package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Request model for signing a credential message")
public class SignCredentialRequestDto {
    @ApiModelProperty(notes = "The message to be signed")
    private String message;

    @ApiModelProperty(notes = "Application ID for key selection")
    private String applicationId;

    @ApiModelProperty(notes = "Reference ID for key selection")
    private String referenceId;
} 