package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerifyRawMessageResponseDto {
    @ApiModelProperty(notes = "Whether the signature is valid", example = "true", required = true)
    private boolean valid;

    @ApiModelProperty(notes = "Validation message", example = "Signature valid", required = true)
    private String message;

    @ApiModelProperty(notes = "Response timestamp in UTC", example = "2024-05-01T12:34:56Z", required = true)
    private String timestamp;
} 