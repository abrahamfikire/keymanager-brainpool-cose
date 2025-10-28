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
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.constant.SignatureConstant;
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
import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.ResponseBody;

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
	
	private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureController.class);
	
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

    

    

    

    

    

    

    @ResponseBody
    @PreAuthorize("hasAnyRole('fayda_cred_client')")
    @PostMapping("/signCredential")
    @ApiOperation(value = "Sign a credential message using ECDSA", notes = "Signs a credential message using the HSM-backed key for the given application and reference ID.")
    public ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> signCredential(
            @RequestBody @Valid io.mosip.kernel.core.http.RequestWrapper<io.mosip.kernel.signature.dto.SignCredentialRequestDto> requestDto) {
        
        String sessionId = SignatureConstant.SESSIONID;
        LOGGER.info(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
            "Received signCredential request. RequestId: {}, ApplicationId: {}", 
            requestDto.getId(), requestDto.getRequest().getApplicationId());
        
        try {
            io.mosip.kernel.signature.dto.SignatureResponseDto responseDto = service.signCredential(requestDto.getRequest());
            io.mosip.kernel.core.http.ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> response = new io.mosip.kernel.core.http.ResponseWrapper<>();
            response.setResponse(responseDto);
            
            LOGGER.info(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
                "SignCredential request completed successfully");
            
            return response;
        } catch (Exception e) {
            LOGGER.error(sessionId, "SIGN_CREDENTIAL_CONTROLLER", SignatureConstant.BLANK,
                "Exception in signCredential controller: {}", e.getMessage(), e);
            throw e;
        }
    }

    @ResponseBody
    @PostMapping("/verifyCredential")
    @ApiOperation(value = "Verify a credential signature using ECDSA", notes = "Verifies a credential signature using the HSM-backed key for the given application and reference ID.")
    public io.mosip.kernel.core.http.ResponseWrapper<Boolean> verifyCredential(
            @RequestBody @Valid io.mosip.kernel.core.http.RequestWrapper<io.mosip.kernel.signature.dto.VerifyCredentialRequestDto> requestDto) {
        boolean valid = service.verifyCredential(requestDto.getRequest());
        io.mosip.kernel.core.http.ResponseWrapper<Boolean> response = new io.mosip.kernel.core.http.ResponseWrapper<>();
        response.setResponse(valid);
        return response;
    }

    
}
