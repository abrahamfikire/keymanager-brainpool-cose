package io.mosip.kernel.signature.dto;

import javax.validation.constraints.NotBlank;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignRawMessageRequestDto {
    @NotBlank
    @ApiModelProperty(notes = "Message to sign", example = "Hello World", required = true)
    private String message;

    @NotBlank
    @ApiModelProperty(notes = "Application id to be used for signing", example = "KERNEL", required = true)
    private String applicationId;

    @NotBlank
    @ApiModelProperty(notes = "Reference id to be used for signing", example = "SIGN", required = true)
    private String referenceId;
} 