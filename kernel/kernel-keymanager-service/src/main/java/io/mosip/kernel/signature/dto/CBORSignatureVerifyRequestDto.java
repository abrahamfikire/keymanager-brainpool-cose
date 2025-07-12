package io.mosip.kernel.signature.dto;

import javax.validation.constraints.NotBlank;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CBORSignatureVerifyRequestDto {
    
    @NotBlank
    @ApiModelProperty(notes = "CBOR Signature data to verify", example = "d83dd28443a10126...", required = true)
    private String cborSignatureData;
    
    @ApiModelProperty(notes = "Application id to be used for verification", example = "KERNEL", required = false)
    private String applicationId;
    
    @ApiModelProperty(notes = "Reference Id", example = "SIGN", required = false)
    private String referenceId;
    
    /**
     * Certificate to be used in CBOR Signature verification.
     */
    @ApiModelProperty(notes = "Certificate to be used in CBOR Signature verification.", example = "", required = false)
    private String certificateData;
    
    /**
     * Flag to validate against trust store.
     */
    @ApiModelProperty(notes = "Flag to validate against trust store.", example = "false", required = false)
    private Boolean validateTrust;
    
    /**
     * Domain to be considered to validate trust store
     */
    @ApiModelProperty(notes = "Domain to be considered to validate trust store.", example = "", required = false)
    private String domain;
} 