package io.mosip.kernel.signatureeeee.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signatureeeee.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureVerifyRequestDto;
import io.mosip.kernel.signatureeeee.dto.JWTSignatureVerifyResponseDto;
import io.mosip.kernel.signatureeeee.dto.PDFSignatureRequestDto;
import io.mosip.kernel.signatureeeee.dto.SignRequestDto;
import io.mosip.kernel.signatureeeee.dto.SignResponseDto;
import io.mosip.kernel.signatureeeee.dto.SignatureResponseDto;
import io.mosip.kernel.signatureeeee.dto.TimestampRequestDto;
import io.mosip.kernel.signatureeeee.dto.ValidatorResponseDto;
import io.mosip.kernel.signatureeeee.service.SignatureService;
import io.mosip.kernel.signatureeeee.service.impl.SignatureServiceImpl;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

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

	@Autowired
	private SignatureServiceImpl signatureServiceImpl;

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
	 * Endpoint to sign data as CBOR/COSE (COSE_Sign1)
	 * @param payload Map of data to sign
	 * @param applicationId Application ID
	 * @param referenceId Reference ID
	 * @return Base64-encoded COSE_Sign1
	 */
	@PostMapping("/v1/signature/cose-sign")
	public String signCose(@RequestBody Map<String, Object> payload,
						   @RequestParam String applicationId,
						   @RequestParam String referenceId) {
		byte[] coseBytes = signatureServiceImpl.generateSignedQRCodePayload(payload, applicationId, referenceId);
		return Base64.getEncoder().encodeToString(coseBytes);
	}

	/**
	 * Endpoint to verify a COSE_Sign1 signature
	 * @param base64CoseSign1 Base64-encoded COSE_Sign1
	 * @param publicKeyPem PEM-encoded public key
	 * @return true if signature is valid, false otherwise
	 */
	@PostMapping("/v1/signature/cose-verify")
	public boolean verifyCose(@RequestParam String base64CoseSign1,
							  @RequestParam String publicKeyPem) {
		byte[] coseBytes = Base64.getDecoder().decode(base64CoseSign1);
		return signatureServiceImpl.verifyCoseSignatureWithPem(coseBytes, publicKeyPem);
	}
}
