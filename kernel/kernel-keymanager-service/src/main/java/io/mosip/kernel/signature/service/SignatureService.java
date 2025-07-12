package io.mosip.kernel.signature.service;

import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyResponseDto;
import io.mosip.kernel.signature.dto.PDFSignatureRequestDto;
import io.mosip.kernel.signature.dto.SignRequestDto;
import io.mosip.kernel.signature.dto.SignatureResponseDto;
import io.mosip.kernel.signature.dto.TimestampRequestDto;
import io.mosip.kernel.signature.dto.ValidatorResponseDto;
import io.mosip.kernel.signature.dto.COSESign1RequestDto;
import io.mosip.kernel.signature.dto.COSESign1ResponseDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyRequestDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyResponseDto;
import io.mosip.kernel.signature.dto.CBORSignatureRequestDto;
import io.mosip.kernel.signature.dto.CBORSignatureResponseDto;
import io.mosip.kernel.signature.dto.CBORSignatureVerifyRequestDto;
import io.mosip.kernel.signature.dto.CBORSignatureVerifyResponseDto;

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

	/**
	 * COSE_Sign1 signature for the inputted data using ES256 algorithm
	 *
	 * @param coseSign1RequestDto the COSESign1RequestDto
	 * @return the COSESign1ResponseDto
	 */
	public COSESign1ResponseDto coseSign1(COSESign1RequestDto coseSign1RequestDto);

	/**
	 * COSE_Sign1 signature verification.
	 *
	 * @param coseSign1VerifyRequestDto the COSESign1VerifyRequestDto
	 * @return the COSESign1VerifyResponseDto
	 */
	public COSESign1VerifyResponseDto coseVerify1(COSESign1VerifyRequestDto coseSign1VerifyRequestDto);

    /**
     * CBOR signature for the inputted data
     *
     * @param cborSignRequestDto the CBORSignatureRequestDto
     * @return the CBORSignatureResponseDto
     */
    public CBORSignatureResponseDto cborSign(CBORSignatureRequestDto cborSignRequestDto);

    /**
     * CBOR signature verification.
     *
     * @param cborSignatureVerifyRequestDto the CBORSignatureVerifyRequestDto
     * @return the CBORSignatureVerifyResponseDto
     */
    public CBORSignatureVerifyResponseDto cborVerify(CBORSignatureVerifyRequestDto cborSignatureVerifyRequestDto);
}
