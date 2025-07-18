package io.mosip.kernel.signature.dto;

import javax.validation.constraints.NotBlank;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerifyRawMessageRequestDto {
    @NotBlank
    @ApiModelProperty(notes = "Message whose signature is to be verified", example = "Hello World", required = true)
    private String message;

    @NotBlank
    @ApiModelProperty(notes = "Base64-encoded signature to verify", example = "MEUCIQDv...", required = true)
    private String signature;

    @NotBlank
    @ApiModelProperty(notes = "Application id to be used for verification", example = "KERNEL", required = true)
    private String applicationId;

    @NotBlank
    @ApiModelProperty(notes = "Reference id to be used for verification", example = "SIGN", required = true)
    private String referenceId;
} 