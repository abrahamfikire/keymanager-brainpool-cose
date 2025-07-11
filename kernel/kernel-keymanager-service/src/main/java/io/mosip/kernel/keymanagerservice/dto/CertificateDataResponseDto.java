package io.mosip.kernel.keymanagerservice.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response class for Certificate Data.
 * 
 * @author Mahammed Taheer
 * @since 1.2.1
 *
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Class representing a Certificate Data Response")
public class CertificateDataResponseDto {

    /**
	 * Field for certificate
	 */
	@ApiModelProperty(notes = "X509 certificate", required = true)
    private String certificateData;
    
	/**
	 * Key creation time
	 */
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
	@ApiModelProperty(notes = "Timestamp of issuance of certificate", required = true)
	private LocalDateTime issuedAt;

	/**
	 * Key expiry time
	 */
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
	@ApiModelProperty(notes = "Timestamp of expiry of certificate", required = true)
    private LocalDateTime expiryAt;
    
	/**
	 * Field for certificate
	 */
	@ApiModelProperty(notes = "Unique Identifier of the key", required = true)
    private String keyId;


}
