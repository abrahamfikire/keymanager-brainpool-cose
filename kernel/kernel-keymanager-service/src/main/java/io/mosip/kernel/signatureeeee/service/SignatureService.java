package io.mosip.kernel.signatureeeee.service;

import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signatureeeee.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureVerifyRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureVerifyResponseDto;
import io.mosip.kernel.signatureeeee.dto.PDFSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.SignRequestDto;
import io.mosip.kernel.signatureeeee.dto.SignatureResponseDto;
import io.mosip.kernel.signatureeeee.dto.TimestampRequestDto;
import io.mosip.kernel.signatureeeee.dto.ValidatorResponseDto;

public interface SignatureService {
	/**
	 * Validate signature
	 * 
	 * @param timestampRequestDto {@link TimestampRequestDto}
	 * @return {@link ValidatorResponseDto}
	 */
	@Deprecated
	public ValidatorResponseDto validate(TimestampRequestDto timestampRequestDto);

	/**
	 * Sign Data.
	 *
	 * @param signRequestDto the signRequestDto
	 * @return the SignatureResponse
	 */
	@Deprecated
	public SignatureResponse sign(SignRequestDto signRequestDto);


	public SignatureResponseDto signPDF(PDFSignatureRequestDto request);

	/**
	 * JSON Web Signature(JWS) for the inputted data using RS256 algorithm
	 *
	 * @param jwtSignRequestDto the jwtSignRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwtSign(JWTSignatureRequestDto jwtSignRequestDto);

	/**
	 * JWT Signature verification.
	 *
	 * @param jwtSignatureVerifyRequestDto the jwtSignatureVerifyRequestDto
	 * @return the JWTSignatureVerifyResponseDto
	 */
	public JWTSignatureVerifyResponseDto jwtVerify(JWTSignatureVerifyRequestDto jwtSignatureVerifyRequestDto);


	/**
	 * JSON Web Signature(JWS) for the inputted data using inputted algorithm
	 *
	 * @param jwsSignRequestDto the JWSSignatureRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto);

}
