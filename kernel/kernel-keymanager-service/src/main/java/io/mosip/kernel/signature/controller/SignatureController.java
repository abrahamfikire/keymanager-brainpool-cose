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
import io.mosip.kernel.signature.dto.CBORSignatureRequestDto;
import io.mosip.kernel.signature.dto.CBORSignatureResponseDto;
import io.mosip.kernel.signature.dto.CBORSignatureVerifyRequestDto;
import io.mosip.kernel.signature.dto.CBORSignatureVerifyResponseDto;
import io.mosip.kernel.signature.dto.SignBinaryRequestDto;
import io.mosip.kernel.signature.dto.SignBinaryResponseDto;
import io.mosip.kernel.signature.dto.VerifyBinaryRequestDto;
import io.mosip.kernel.signature.dto.VerifyBinaryResponseDto;
import io.mosip.kernel.signature.dto.QRCodeRequestDto;
import io.mosip.kernel.signature.dto.QRCodeResponseDto;
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

    /**
     * Function to do CBOR signature for the inputted data
     *
     * @param requestDto {@link CBORSignatureRequestDto} having required fields.
     * @return The {@link CBORSignatureResponseDto}
     */
    @ResponseFilter
    @PostMapping(value = "/cborSign")
    public ResponseWrapper<CBORSignatureResponseDto> cborSign(@RequestBody @Valid RequestWrapper<CBORSignatureRequestDto> requestDto) {
        String sessionId = SignatureConstant.SESSIONID;
        
        LOGGER.info(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                "Received CBOR signing request. RequestId: {}, ApplicationId: {}, ReferenceId: {}", 
                requestDto.getId(), 
                requestDto.getRequest().getApplicationId(), 
                requestDto.getRequest().getReferenceId());
        
        // Log input data details for debugging
        String dataToSign = requestDto.getRequest().getDataToSign();
        if (dataToSign != null) {
            LOGGER.debug(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                    "Input dataToSign length: {} characters", dataToSign.length());
            
            // Log first and last few characters for debugging (without exposing full data)
            if (dataToSign.length() > 20) {
                LOGGER.debug(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                        "Input dataToSign preview: {}...{}", 
                        dataToSign.substring(0, 10), 
                        dataToSign.substring(dataToSign.length() - 10));
            } else {
                LOGGER.debug(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                        "Input dataToSign: {}", dataToSign);
            }
            
            // Check for common issues
            if (dataToSign.length() % 2 != 0) {
                LOGGER.warn(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                        "Input hex string has odd number of characters: {}", dataToSign.length());
            }
        } else {
            LOGGER.warn(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                    "Input dataToSign is null");
        }
        
        try {
            CBORSignatureResponseDto signatureResponse = service.cborSign(requestDto.getRequest());
            ResponseWrapper<CBORSignatureResponseDto> response = new ResponseWrapper<>();
            response.setResponse(signatureResponse);
            
            // Log response details
            if (signatureResponse.getCborSignedData() != null) {
                LOGGER.info(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                        "CBOR signing completed successfully. Output length: {} characters", 
                        signatureResponse.getCborSignedData().length());
            } else {
                LOGGER.warn(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                        "CBOR signing completed but output is null");
            }
            
            return response;
        } catch (Exception e) {
            LOGGER.error(sessionId, "CBOR_SIGN_CONTROLLER", SignatureConstant.BLANK,
                    "Exception in CBOR signing controller: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Function to verify CBOR signature
     *
     * @param requestDto {@link CBORSignatureVerifyRequestDto} having required fields.
     * @return The {@link CBORSignatureVerifyResponseDto}
     */
    @ResponseFilter
    @PostMapping(value = "/cborVerify")
    public ResponseWrapper<CBORSignatureVerifyResponseDto> cborVerify(@RequestBody @Valid RequestWrapper<CBORSignatureVerifyRequestDto> requestDto) {
        String sessionId = SignatureConstant.SESSIONID;
        
        LOGGER.info(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                "Received CBOR verification request. RequestId: {}, ApplicationId: {}, ReferenceId: {}", 
                requestDto.getId(), 
                requestDto.getRequest().getApplicationId(), 
                requestDto.getRequest().getReferenceId());
        
        // Log input data details for debugging
        String cborSignatureData = requestDto.getRequest().getCborSignatureData();
        if (cborSignatureData != null) {
            LOGGER.debug(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                    "Input cborSignatureData length: {} characters", cborSignatureData.length());
            
            // Log first and last few characters for debugging
            if (cborSignatureData.length() > 20) {
                LOGGER.debug(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                        "Input cborSignatureData preview: {}...{}", 
                        cborSignatureData.substring(0, 10), 
                        cborSignatureData.substring(cborSignatureData.length() - 10));
            } else {
                LOGGER.debug(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                        "Input cborSignatureData: {}", cborSignatureData);
            }
        } else {
            LOGGER.warn(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                    "Input cborSignatureData is null");
        }
        
        try {
            CBORSignatureVerifyResponseDto signatureResponse = service.cborVerify(requestDto.getRequest());
            ResponseWrapper<CBORSignatureVerifyResponseDto> response = new ResponseWrapper<>();
            response.setResponse(signatureResponse);
            
            // Log response details
            LOGGER.info(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                    "CBOR verification completed. Result: {}, Message: {}", 
                    signatureResponse.isSignatureValid() ? "VALID" : "INVALID",
                    signatureResponse.getMessage());
            
            return response;
        } catch (Exception e) {
            LOGGER.error(sessionId, "CBOR_VERIFY_CONTROLLER", SignatureConstant.BLANK,
                    "Exception in CBOR verification controller: {}", e.getMessage(), e);
            throw e;
        }
    }

@ResponseBody
@PostMapping("/signBinary")
@ApiOperation(value = "Sign binary data using ECDSA", notes = "Signs binary data (base64-encoded) using the HSM-backed key for the given application and reference ID.")
public ResponseWrapper<SignBinaryResponseDto> signBinary(
        @RequestBody @Valid RequestWrapper<SignBinaryRequestDto> requestDto) {
    byte[] data = java.util.Base64.getDecoder().decode(requestDto.getRequest().getDataBase64());
    byte[] signature = service.signBinary(data,
            requestDto.getRequest().getApplicationId(),
            requestDto.getRequest().getReferenceId());
    String signatureBase64 = java.util.Base64.getEncoder().encodeToString(signature);
    SignBinaryResponseDto responseDto = new SignBinaryResponseDto();
    responseDto.setSignatureBase64(signatureBase64);
    responseDto.setTimestamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString());
    ResponseWrapper<SignBinaryResponseDto> response = new ResponseWrapper<>();
    response.setResponse(responseDto);
    return response;
}

@ResponseBody
@PostMapping("/verifyBinary")
@ApiOperation(value = "Verify binary data signature using ECDSA", notes = "Verifies a signature (base64-encoded) over binary data (base64-encoded) using the HSM-backed key for the given application and reference ID.")
public ResponseWrapper<VerifyBinaryResponseDto> verifyBinary(
        @RequestBody @Valid RequestWrapper<VerifyBinaryRequestDto> requestDto) {
    byte[] data = java.util.Base64.getDecoder().decode(requestDto.getRequest().getDataBase64());
    byte[] signature = java.util.Base64.getDecoder().decode(requestDto.getRequest().getSignatureBase64());
    boolean valid = service.verifyBinary(data,
            signature,
            requestDto.getRequest().getApplicationId(),
            requestDto.getRequest().getReferenceId());
    VerifyBinaryResponseDto responseDto = new VerifyBinaryResponseDto();
    responseDto.setValid(valid);
    responseDto.setMessage(valid ? "Signature valid" : "Signature invalid");
    responseDto.setTimestamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString());
    ResponseWrapper<VerifyBinaryResponseDto> response = new ResponseWrapper<>();
    response.setResponse(responseDto);
    return response;
}

    @ResponseBody
    @PostMapping("/signCredential")
    @ApiOperation(value = "Sign a credential message using ECDSA", notes = "Signs a credential message using the HSM-backed key for the given application and reference ID.")
    public ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> signCredential(
            @RequestBody @Valid io.mosip.kernel.core.http.RequestWrapper<io.mosip.kernel.signature.dto.SignCredentialRequestDto> requestDto) {
        io.mosip.kernel.signature.dto.SignatureResponseDto responseDto = service.signCredential(requestDto.getRequest());
        io.mosip.kernel.core.http.ResponseWrapper<io.mosip.kernel.signature.dto.SignatureResponseDto> response = new io.mosip.kernel.core.http.ResponseWrapper<>();
        response.setResponse(responseDto);
        return response;
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

    @ResponseBody
    @PostMapping("/generateQRCode")
    @ApiOperation(value = "Generate QR code for offline verification", 
                  notes = "Creates a QR code containing signed data and verification information for offline mobile app verification")
    public ResponseWrapper<QRCodeResponseDto> generateQRCode(
            @RequestBody @Valid RequestWrapper<QRCodeRequestDto> requestDto) {
        QRCodeResponseDto responseDto = service.generateQRCode(requestDto.getRequest());
        ResponseWrapper<QRCodeResponseDto> response = new ResponseWrapper<>();
        response.setResponse(responseDto);
        return response;
    }
}
