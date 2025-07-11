package io.mosip.kernel.clientcrypto.controller;


import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.clientcrypto.dto.PublicKeyRequestDto;
import io.mosip.kernel.clientcrypto.dto.PublicKeyResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmCryptoRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmCryptoResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignVerifyRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignVerifyResponseDto;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoManagerService;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

/**
 * @author Anusha Sunkada
 * @since 1.1.2
 */

@CrossOrigin
@RestController
@Api(value = "Operation related to offline Encryption and Decryption", tags = { "clientcrypto" })
public class ClientCryptoController {

    @Autowired
    private ClientCryptoManagerService clientCryptoManagerService;
    /**
     *
     * @param tpmSignRequestDtoRequestWrapper
     * @return
     */
    @ApiOperation(value = "Sign data using tpm", notes = "Sign data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
	})
    //@PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPostcssign())")
    @ResponseFilter
    @PostMapping(value = "/cssign", produces = "application/json")
    public ResponseWrapper<TpmSignResponseDto> signData(@RequestBody @Valid RequestWrapper<TpmSignRequestDto>
                                                                             tpmSignRequestDtoRequestWrapper) {
        ResponseWrapper<TpmSignResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csSign(tpmSignRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmSignVerifyRequestDtoRequestWrapper
     * @return
     */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @ApiOperation(value = "Verify signature", notes  = "Verify signature", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
        })
       // @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPostcsverifysign())")

    @ResponseFilter
    @PostMapping(value = "/csverifysign", produces = "application/json")
    public ResponseWrapper<TpmSignVerifyResponseDto> verifySignature(@RequestBody @Valid RequestWrapper<TpmSignVerifyRequestDto>
                                                                  tpmSignVerifyRequestDtoRequestWrapper) {
        ResponseWrapper<TpmSignVerifyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csVerify(tpmSignVerifyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmCryptoRequestDtoRequestWrapper
     * @return
     */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @ApiOperation(value  = "Encrypt data using tpm", notes = "Encrypt data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
    })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
   // @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmencrypt())")
    @ResponseFilter
    @PostMapping(value = "/tpmencrypt", produces = "application/json")
    public ResponseWrapper<TpmCryptoResponseDto> tpmEncrypt(@RequestBody @Valid RequestWrapper<TpmCryptoRequestDto>
                                                                             tpmCryptoRequestDtoRequestWrapper) {
        ResponseWrapper<TpmCryptoResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csEncrypt(tpmCryptoRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmCryptoRequestDtoRequestWrapper
     * @return
     */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")     
    @ApiOperation(value  = "Decrypt data using tpm", notes = "Decrypt data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
    })
   // @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmdecrypt())")
    @ResponseFilter
    @PostMapping(value = "/tpmdecrypt", produces = "application/json")
    public ResponseWrapper<TpmCryptoResponseDto> tpmDecrypt(@RequestBody @Valid RequestWrapper<TpmCryptoRequestDto>
                                                                    tpmCryptoRequestDtoRequestWrapper) {
        ResponseWrapper<TpmCryptoResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csDecrypt(tpmCryptoRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param publicKeyRequestDtoRequestWrapper
     * @return
     */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @ApiOperation(value  = "Get signinging public key", notes = "Get signinging public key", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
    })
  //  @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmsigningpublickey())")
    @ResponseFilter
    @PostMapping(value = "/tpmsigning/publickey", produces = "application/json")
    public ResponseWrapper<PublicKeyResponseDto> getSigningPublicKey(@RequestBody @Valid RequestWrapper<PublicKeyRequestDto>
                                                                    publicKeyRequestDtoRequestWrapper) {
        ResponseWrapper<PublicKeyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.getSigningPublicKey(publicKeyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param publicKeyRequestDtoRequestWrapper
     * @return
     */
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @ApiOperation(value  = "et encryption public key", notes = "et encryption public key", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
        })
   // @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmencryptionpublickey())")
    @ResponseFilter
    @PostMapping(value = "/tpmencryption/publickey", produces = "application/json")
    public ResponseWrapper<PublicKeyResponseDto> getEncPublicKey(@RequestBody @Valid RequestWrapper<PublicKeyRequestDto>
                                                                             publicKeyRequestDtoRequestWrapper) {
        ResponseWrapper<PublicKeyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.getEncPublicKey(publicKeyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }
}
