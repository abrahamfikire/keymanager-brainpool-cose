package io.mosip.kernel.signature.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signature.dto.COSESign1RequestDto;
import io.mosip.kernel.signature.dto.COSESign1ResponseDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyRequestDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyResponseDto;
import io.mosip.kernel.signature.dto.PDFSignatureRequestDto;
import io.mosip.kernel.signature.dto.SignRequestDto;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.dto.SignatureResponseDto;
import io.mosip.kernel.signature.dto.TimestampRequestDto;
import io.mosip.kernel.signature.dto.ValidatorResponseDto;
import io.mosip.kernel.signature.service.SignatureService;

/**
 * 
 * @author Uday Kumar
 * @since 1.0.0
 *
 */
@SuppressWarnings("java:S5122") // Need CrossOrigin access for all the APIs, added to ignore in sonarCloud Security hotspots.
@RestController
@CrossOrigin
public class SignatureController {
	/**
	 * Crypto signature Service field with functions related to signature
	 */
	@Autowired
	SignatureService service;

	/**
	 * Function to sign response
	 * 
	 * @param requestDto {@link SignRequestDto} having required fields.
	 * @return The {@link SignatureResponse}
	 */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PostMapping(value = "/sign")
	@Deprecated
	public ResponseWrapper<SignResponseDto> sign(@RequestBody @Valid RequestWrapper<SignRequestDto> requestDto) {
		SignatureResponse signatureResponse = service.sign(requestDto.getRequest());
		SignResponseDto signResponse = new SignResponseDto();
		signResponse.setTimestamp(signatureResponse.getTimestamp());
		signResponse.setSignature(signatureResponse.getData());
		ResponseWrapper<SignResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signResponse);
		return response;
	}

	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN')")
	@ResponseFilter
	@PostMapping(value = "/validate")
	@Deprecated
	public ResponseWrapper<ValidatorResponseDto> validate(
			@RequestBody @Valid RequestWrapper<TimestampRequestDto> timestampRequestDto) {
		ResponseWrapper<ValidatorResponseDto> response = new ResponseWrapper<>();
		response.setResponse(service.validate(timestampRequestDto.getRequest()));
		return response;
	}

	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PostMapping("/pdf/sign")
	public ResponseWrapper<SignatureResponseDto> signPDF(
			@RequestBody @Valid RequestWrapper<PDFSignatureRequestDto> signatureResponseDto) {
		ResponseWrapper<SignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(service.signPDF(signatureResponseDto.getRequest()));
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the inputted data using RS256 algorithm
	 * 
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PostMapping(value = "/jwtSign")
	public ResponseWrapper<JWTSignatureResponseDto> jwtSign(@RequestBody @Valid RequestWrapper<JWTSignatureRequestDto> requestDto) {
		JWTSignatureResponseDto signatureResponse = service.jwtSign(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		return response;
	}

	/**
	 * Function to JWT Signature verification
	 * 
	 * @param requestDto {@link JWTSignatureVerifyRequestDto} having required fields.
	 * @return The {@link JWTSignatureVerifyResponseDto}
	 */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PostMapping(value = "/jwtVerify")
	public ResponseWrapper<JWTSignatureVerifyResponseDto> jwtVerify(@RequestBody @Valid RequestWrapper<JWTSignatureVerifyRequestDto> requestDto) {
		JWTSignatureVerifyResponseDto signatureResponse = service.jwtVerify(requestDto.getRequest());
		ResponseWrapper<JWTSignatureVerifyResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the inputted data using inputted algorithm. Default Algorithm PS256.
	 * 
	 * @param requestDto {@link JWSSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@ResponseFilter
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT','CREDENTIAL_ISSUANCE')")
	@PostMapping(value = "/jwsSign")
	public ResponseWrapper<JWTSignatureResponseDto> jwsSign(
			@RequestBody @Valid RequestWrapper<JWSSignatureRequestDto> requestDto) {
		JWTSignatureResponseDto signatureResponse = service.jwsSign(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		return response;
	}

    /**
     * Function to do COSE_Sign1 signature for the inputted data using ES256 algorithm
     *
     * @param requestDto {@link COSESign1RequestDto} having required fields.
     * @return The {@link COSESign1ResponseDto}
     */
    @ResponseFilter
    @PostMapping(value = "/coseSign1")
    public ResponseWrapper<COSESign1ResponseDto> coseSign1(@RequestBody @Valid RequestWrapper<COSESign1RequestDto> requestDto) {
        COSESign1ResponseDto signatureResponse = service.coseSign1(requestDto.getRequest());
        ResponseWrapper<COSESign1ResponseDto> response = new ResponseWrapper<>();
        response.setResponse(signatureResponse);
        return response;
    }

    /**
     * Function to COSE_Sign1 signature verification
     *
     * @param requestDto {@link COSESign1VerifyRequestDto} having required fields.
     * @return The {@link COSESign1VerifyResponseDto}
     */
    @ResponseFilter
    @PostMapping(value = "/coseVerify1")
    public ResponseWrapper<COSESign1VerifyResponseDto> coseVerify1(@RequestBody @Valid RequestWrapper<COSESign1VerifyRequestDto> requestDto) {
        COSESign1VerifyResponseDto signatureResponse = service.coseVerify1(requestDto.getRequest());
        ResponseWrapper<COSESign1VerifyResponseDto> response = new ResponseWrapper<>();
        response.setResponse(signatureResponse);
        return response;
    }
}
