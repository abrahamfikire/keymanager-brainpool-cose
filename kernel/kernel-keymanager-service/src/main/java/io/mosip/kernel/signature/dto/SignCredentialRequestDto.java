package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Request model for signing a credential message")
public class SignCredentialRequestDto {
    @NotBlank(message = "Message cannot be null or empty")
    @Size(max = 1048576, message = "Message size cannot exceed 1MB")
    @ApiModelProperty(notes = "The message to be signed (Base64 encoded, max 1MB)")
    private String message;

    @NotBlank(message = "ApplicationId cannot be null or empty")
    @Pattern(regexp = "^[A-Za-z0-9_-]{1,50}$", message = "Invalid ApplicationId format")
    @ApiModelProperty(notes = "Application ID for key selection (alphanumeric, max 50 chars)")
    private String applicationId;

    @NotBlank(message = "ReferenceId cannot be null or empty")
    @Pattern(regexp = "^[A-Za-z0-9_-]{1,50}$", message = "Invalid ReferenceId format")
    @ApiModelProperty(notes = "Reference ID for key selection (alphanumeric, max 50 chars)")
    private String referenceId;
} 