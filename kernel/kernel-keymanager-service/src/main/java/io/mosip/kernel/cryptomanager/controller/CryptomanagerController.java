/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.controller;

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
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashRequestDto;
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTCipherResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTDecryptRequestDto;
import io.mosip.kernel.cryptomanager.dto.JWTEncryptRequestDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

/**
 * Rest Controller for Crypto-Manager-Service
 * 
 * @author Urvil Joshi
 * @author Srinivasan
 *
 * @since 1.0.0
 */
@SuppressWarnings("java:S5122") // Need CrossOrigin access for all the APIs, added to ignore in sonarCloud Security hotspots.
@CrossOrigin
@RestController
@Api(value = "Operation related to Encryption and Decryption", tags = { "cryptomanager" })
public class CryptomanagerController {

	/**
	 * {@link CryptomanagerService} instance
	 */
	@Autowired
	private CryptomanagerService cryptomanagerService;

	/**
	 * Controller for Encrypt the data
	 * 
	 * @param cryptomanagerRequestDto {@link CryptomanagerRequestDto} request
	 * @return {@link CryptomanagerResponseDto} encrypted Data
	 */
	@ApiOperation(value = "Encrypt the data", notes = "Encrypt the data", tags = { "cryptomanager" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message  = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found") })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostencrypt())")
	@ResponseFilter
	@PostMapping(value = "/encrypt", produces = "application/json")
	public ResponseWrapper<CryptomanagerResponseDto> encrypt(
			@ApiParam("Salt and Data to encrypt in BASE64 encoding with meta-data") @RequestBody @Valid RequestWrapper<CryptomanagerRequestDto> cryptomanagerRequestDto) {
		ResponseWrapper<CryptomanagerResponseDto> response = new ResponseWrapper<>();
		response.setResponse(cryptomanagerService.encrypt(cryptomanagerRequestDto.getRequest()));
		return response;
	}

	/**
	 * Controller for Decrypt the data
	 * 
	 * @param cryptomanagerRequestDto {@link CryptomanagerRequestDto} request
	 * @return {@link CryptomanagerResponseDto} decrypted Data
	 */
	@ApiOperation(value  = "Decrypt the data", notes = "Decrypt the data", tags = { "cryptomanager" })
	@ApiResponses({
		@ApiResponse(code = 200, message  = "Success or you may find errors in error array in response"),
		@ApiResponse(code = 401, message = "Unauthorized"),
		@ApiResponse(code = 403, message = "Forbidden"),
		@ApiResponse(code = 404, message = "Not Found") })
//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
@ResponseFilter
//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostdecrypt())")
	@PostMapping(value = "/decrypt", produces = "application/json")
	public ResponseWrapper<CryptomanagerResponseDto> decrypt(
			@ApiParam("Salt and Data to decrypt in BASE64 encoding with meta-data") @RequestBody @Valid RequestWrapper<CryptomanagerRequestDto> cryptomanagerRequestDto) {
		ResponseWrapper<CryptomanagerResponseDto> response = new ResponseWrapper<>();
		response.setResponse(cryptomanagerService.decrypt(cryptomanagerRequestDto.getRequest()));
		return response;
	}

	/**
	 * Controller for Encrypt the data Using Pin
	 * 
	 * @param requestDto {@link CryptoWithPinRequestDto} request
	 * @return {@link CryptoWithPinResponseDto} encrypted Data
	 */
	@ApiOperation(value = "Encrypt the data with pin", notes = "Encrypt the data with pin", tags = {
		"cryptomanager" })
		@ApiResponses({
			@ApiResponse(code = 200, message  = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found") })
//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
@ResponseFilter
//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostencryptwithpin())")
	@PostMapping(value = "/encryptWithPin", produces = "application/json")
	public ResponseWrapper<CryptoWithPinResponseDto> encryptWithPin(
			@ApiParam("Pin and Data to encrypt") @RequestBody @Valid RequestWrapper<CryptoWithPinRequestDto> requestDto) {
		ResponseWrapper<CryptoWithPinResponseDto> responseDto = new ResponseWrapper<>();
		responseDto.setResponse(cryptomanagerService.encryptWithPin(requestDto.getRequest()));
		return responseDto;
	}

	/**
	 * Controller for Decrypt the data Using Pin
	 * 
	 * @param requestDto {@link CryptoWithPinRequestDto} request
	 * @return {@link CryptoWithPinResponseDto} decrypted Data
	 */
	@ApiOperation(value = "Decrypt the data with pin", notes = "Decrypt the data with pin", tags = {
		"cryptomanager" })
		@ApiResponses({
			@ApiResponse(code = 200, message  = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found") })
//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
@ResponseFilter
//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostdecryptwithpin())")
	@PostMapping(value = "/decryptWithPin", produces = "application/json")
	public ResponseWrapper<CryptoWithPinResponseDto> decryptWithPin(
			@ApiParam("Pin and Data to decrypt") @RequestBody @Valid RequestWrapper<CryptoWithPinRequestDto> requestDto) {
		ResponseWrapper<CryptoWithPinResponseDto> responseDto = new ResponseWrapper<>();
		responseDto.setResponse(cryptomanagerService.decryptWithPin(requestDto.getRequest()));
		return responseDto;
	}

	/**
	 * Controller to Encrypt the data using JSON Web Encryption
	 * 
	 * @param jwtCipherRequestDto {@link JWTEncryptRequestDto} request
	 * @return {@link JWTCipherResponseDto} encrypted Data
	 */
	@ApiOperation(value = "JWE Data Encryption", notes = "Performs JSON Web Encrypt for the given data", tags = { "cryptomanager" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
	})
	//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostjwtencrypt())")
	@ResponseFilter
	@PostMapping(value = "/jwtEncrypt", produces = "application/json")
	public ResponseWrapper<JWTCipherResponseDto> jwtEncrypt(
			@ApiParam("Data to encrypt in BASE64 encoding with meta-data") @RequestBody @Valid RequestWrapper<JWTEncryptRequestDto> jwtCipherRequestDto) {
		ResponseWrapper<JWTCipherResponseDto> response = new ResponseWrapper<>();
		response.setResponse(cryptomanagerService.jwtEncrypt(jwtCipherRequestDto.getRequest()));
		return response;
	}

	/**
	 * Controller to Decrypt the data using JSON Web Encryption
	 * 
	 * @param jwtCipherRequestDto {@link JWTEncryptRequestDto} request
	 * @return {@link JWTCipherResponseDto} decrypted Data
	 */
	@ApiOperation(value = "JWE Data Decryption", notes = "Performs JSON Web Decrypt for the given encrypted data", tags = { "cryptomanager" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
	})
	@ResponseFilter
	//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostjwtdecrypt())")
	@PostMapping(value = "/jwtDecrypt", produces = "application/json")
	public ResponseWrapper<JWTCipherResponseDto> jwtDecrypt(
			@ApiParam("Data to decrypt in BASE64 encoding with meta-data") @RequestBody @Valid RequestWrapper<JWTDecryptRequestDto> jwtCipherRequestDto) {
		ResponseWrapper<JWTCipherResponseDto> response = new ResponseWrapper<>();
		response.setResponse(cryptomanagerService.jwtDecrypt(jwtCipherRequestDto.getRequest()));
		return response;
	}

	/**
	 * Controller to create Argon2 HASH for the input data. 
	 * 
	 * @param argon2GenHashRequestDto {@link Argon2GenerateHashRequestDto} request
	 * @return {@link Argon2GenerateHashResponseDto} the hash value and salt value
	 */
	@ApiOperation(value = "Argon2 hash generation", notes = "Performs Hash generation using Argon2 algorithm", tags = { "cryptomanager" })
	@ApiResponses(value = {
			@ApiResponse(code = 200, message = "Success or you may find errors in error array in response"),
			@ApiResponse(code = 401, message = "Unauthorized"),
			@ApiResponse(code = 403, message = "Forbidden"),
			@ApiResponse(code = 404, message = "Not Found")
	})
	//@PreAuthorize("hasAnyRole(@cryptoManagerAuthRoles.getPostgenerateargon2hash())")
	@ResponseFilter
	@PostMapping(value = "/generateArgon2Hash", produces = "application/json")
	public ResponseWrapper<Argon2GenerateHashResponseDto> generateArgon2Hash(
			@ApiParam("Data to generate Argon2 ") @RequestBody @Valid RequestWrapper<Argon2GenerateHashRequestDto> argon2GenHashRequestDto) {
		ResponseWrapper<Argon2GenerateHashResponseDto> response = new ResponseWrapper<>();
		response.setResponse(cryptomanagerService.generateArgon2Hash(argon2GenHashRequestDto.getRequest()));
		return response;
	}
}
