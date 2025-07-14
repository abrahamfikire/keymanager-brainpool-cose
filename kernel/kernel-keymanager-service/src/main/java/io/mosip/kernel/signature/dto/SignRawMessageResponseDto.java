package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignRawMessageResponseDto {
    @ApiModelProperty(notes = "Base64-encoded signature", example = "MEUCIQDv...", required = true)
    private String signature;

    @ApiModelProperty(notes = "Response timestamp in UTC", example = "2024-05-01T12:34:56Z", required = true)
    private String timestamp;
} 