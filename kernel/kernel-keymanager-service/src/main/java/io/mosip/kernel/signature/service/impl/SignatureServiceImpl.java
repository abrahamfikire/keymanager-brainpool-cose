package io.mosip.kernel.signature.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.SecretKey;

//import com.mchange.util.Base64Encoder;
import io.ipfs.multibase.Multibase;
import io.mosip.kernel.keymanagerservice.exception.InvalidFormatException;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.apache.commons.codec.binary.Base64;
//import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.JsonWebSignatureAlgorithm;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSHeader;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.pdfgenerator.model.Rectangle;
import io.mosip.kernel.core.pdfgenerator.spi.PDFGenerator;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonMappingException;
import io.mosip.kernel.core.util.exception.JsonParseException;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.PublicKeyResponse;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustRequestDto;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustResponeDto;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.exception.CertificateNotValidException;
import io.mosip.kernel.signature.exception.PublicKeyParseException;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.util.SignatureUtil;
import javax.annotation.PostConstruct;
import io.mosip.kernel.signature.dto.COSESign1RequestDto;
import io.mosip.kernel.signature.dto.COSESign1ResponseDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyRequestDto;
import io.mosip.kernel.signature.dto.COSESign1VerifyResponseDto;
import io.mosip.kernel.signature.util.COSESign1Util;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORizer;
import com.authlete.cose.constants.COSEAlgorithms;
import com.authlete.cose.COSEProtectedHeader;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSEUnprotectedHeader;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEVerifier;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSEMessage;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import com.authlete.cwt.CWT;
import com.authlete.cwt.CWTClaimsSet;
import com.authlete.cwt.CWTClaimsSetBuilder;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.util.Map;
import java.util.Optional;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.authlete.cbor.CBORMalformedUtf8Exception;
import com.authlete.cbor.CBORInsufficientDataException;
import org.bouncycastle.asn1.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.Signature;
import java.security.NoSuchProviderException;
import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PostMapping;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.ResponseBody;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.signature.dto.SignRawMessageRequestDto;
import io.mosip.kernel.signature.dto.SignRawMessageResponseDto;
import io.mosip.kernel.signature.dto.VerifyRawMessageRequestDto;
import io.mosip.kernel.signature.dto.VerifyRawMessageResponseDto;


/**
 * @author Uday Kumar
 * @author Urvil
 *
 */
@Service
public class SignatureServiceImpl implements SignatureService, SignatureServicev2 {
	private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureServiceImpl.class);

	@Autowired
	private KeymanagerService keymanagerService;

	@Autowired
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

	@Value("${mosip.kernel.keygenerator.asymmetric-algorithm-name}")
	private String asymmetricAlgorithmName;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationid;

	/** The sign refid. */
	@Value("${mosip.sign.refid:SIGN}")
	private String signRefid;

	@Value("${mosip.kernel.crypto.sign-algorithm-name:RS256}")
	private String signAlgorithm;

	@Value("${mosip.kernel.keymanager.jwtsign.validate.json:true}")
	private boolean confValidateJson;

	@Value("${mosip.kernel.keymanager.jwtsign.include.keyid:true}")
	private boolean includeKeyId;

	@Value("${mosip.kernel.keymanager.jwtsign.enable.secp256k1.algorithm:true}")
	private boolean enableSecp256k1Algo;

	/**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

	@Autowired
	private PDFGenerator pdfGenerator;

	/**
	 * Instance for PartnerCertificateManagerService
	 */
	@Autowired
	PartnerCertificateManagerService partnerCertManagerService;

	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	@Autowired
	ECKeyStore ecKeyStore;

	private static Map<String, SignatureProvider> SIGNATURE_PROVIDER = new HashMap<>();

	AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;

	static {
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST, new PS256SIgnatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST, new Ed25519SignatureProviderImpl());
	}

	private static Map<String, String> JWT_SIGNATURE_ALGO_IDENT = new HashMap<>();
	static {
		JWT_SIGNATURE_ALGO_IDENT.put(SignatureConstant.BLANK, AlgorithmIdentifiers.RSA_USING_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(SignatureConstant.REF_ID_SIGN_CONST, AlgorithmIdentifiers.RSA_USING_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_BRAINPOOLP256R1_SIGN.name(), "ES256-BRAINPOOL");
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.ED25519_SIGN.name(), AlgorithmIdentifiers.EDDSA);
	}

	@PostConstruct
	public void init() {
		KeyGeneratorUtils.loadClazz();
		// Add BouncyCastle provider for SoftHSM2 compatibility
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// Log all available security providers for debugging
		LOGGER.info(SignatureConstant.SESSIONID, "INIT", SignatureConstant.BLANK,
				"Available security providers:");
		for (java.security.Provider provider : Security.getProviders()) {
			LOGGER.info(SignatureConstant.SESSIONID, "INIT", SignatureConstant.BLANK,
					"Provider: {} - {}", provider.getName(), provider.getInfo());
		}
		
		if (enableSecp256k1Algo) {
			AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory =
					AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory();
			jwsAlgorithmFactory.registerAlgorithm(new EcdsaSECP256K1UsingSha256());
			jwsAlgorithmFactory.registerAlgorithm(new EcdsaBrainpoolP256r1UsingSha256());
		}
	}

	@Override
	public SignatureResponse sign(SignRequestDto signRequestDto) {
		SignatureRequestDto signatureRequestDto = new SignatureRequestDto();
		signatureRequestDto.setApplicationId(signApplicationid);
		signatureRequestDto.setReferenceId(signRefid);
		signatureRequestDto.setData(signRequestDto.getData());
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		signatureRequestDto.setTimeStamp(timestamp);
		SignatureResponseDto signatureResponseDTO = sign(signatureRequestDto);
		return new SignatureResponse(signatureResponseDTO.getData(), DateUtils.convertUTCToLocalDateTime(timestamp));
	}

	private SignatureResponseDto sign(SignatureRequestDto signatureRequestDto) {
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(
				signatureRequestDto.getApplicationId(), Optional.of(signatureRequestDto.getReferenceId()),
				signatureRequestDto.getTimeStamp());
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(signatureRequestDto.getTimeStamp()));
		String encryptedSignedData = null;
		if (certificateResponse.getCertificateEntry() != null) {
			encryptedSignedData = cryptoCore.sign(signatureRequestDto.getData().getBytes(),
					certificateResponse.getCertificateEntry().getPrivateKey());
		}
		return new SignatureResponseDto(encryptedSignedData);
	}

	@Override
	public ValidatorResponseDto validate(TimestampRequestDto timestampRequestDto) {

		PublicKeyResponse<String> publicKeyResponse = keymanagerService.getSignPublicKey(signApplicationid,
				DateUtils.formatToISOString(timestampRequestDto.getTimestamp()), Optional.of(signRefid));
		boolean status;
		try {
			PublicKey publicKey = KeyFactory.getInstance(asymmetricAlgorithmName)
					.generatePublic(new X509EncodedKeySpec(CryptoUtil.decodeBase64(publicKeyResponse.getPublicKey())));
			status = cryptoCore.verifySignature(timestampRequestDto.getData().getBytes(),
					timestampRequestDto.getSignature(), publicKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
			throw new PublicKeyParseException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
					exception.getMessage(), exception);
		}

		if (status) {
			ValidatorResponseDto response = new ValidatorResponseDto();
			response.setMessage(SignatureConstant.VALIDATION_SUCCESSFUL);
			response.setStatus(SignatureConstant.SUCCESS);
			return response;
		} else {
			throw new SignatureFailureException(SignatureErrorCode.NOT_VALID.getErrorCode(),
					SignatureErrorCode.NOT_VALID.getErrorMessage(), null);
		}

	}

	@Override
	public SignatureResponseDto signPDF(PDFSignatureRequestDto request) {
		SignatureCertificate signatureCertificate = keymanagerService.getSignatureCertificate(
				request.getApplicationId(), Optional.of(request.getReferenceId()), request.getTimeStamp());
		LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
				"Signature fetched from hsm " + signatureCertificate);
		Rectangle rectangle = new Rectangle(request.getLowerLeftX(), request.getLowerLeftY(), request.getUpperRightX(),
				request.getUpperRightY());
		OutputStream outputStream;
		try {
			String providerName = signatureCertificate.getProviderName();
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
					" Keystore Provider Name found: " + providerName);

			// Arrays.stream(Security.getProviders()).forEach(x -> {
			// 	LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
			// 			"provider name " + x.getName());
			// 	LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
			// 			"provider info " + x.getInfo());
			// });
			// LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
			// 		"all providers ");
			outputStream = pdfGenerator.signAndEncryptPDF(CryptoUtil.decodeBase64(request.getData()), rectangle,
					request.getReason(), request.getPageNumber(), Security.getProvider(providerName),
					signatureCertificate.getCertificateEntry(), request.getPassword());
		} catch (IOException | GeneralSecurityException e) {
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
					KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorMessage() + " " + e.getMessage());
		}
		SignatureResponseDto signatureResponseDto = new SignatureResponseDto();
		signatureResponseDto.setData(CryptoUtil.encodeBase64(((ByteArrayOutputStream) outputStream).toByteArray()));
		return signatureResponseDto;
	}

	@Override
	public JWTSignatureResponseDto jwtSign(JWTSignatureRequestDto jwtSignRequestDto) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request.");

		// boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(jwtSignRequestDto.getApplicationId());
		// if (!hasAcccess) {
		// 	LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
		// 				"Signing Data is not allowed for the authenticated user for the provided application id. " +
		// 				" App Id: " + jwtSignRequestDto.getApplicationId());
		// 	throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
		// 		SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		// }

		String reqDataToSign = jwtSignRequestDto.getDataToSign();
		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		String decodedDataToSign = new String(CryptoUtil.decodeBase64(reqDataToSign));
		if (confValidateJson && !SignatureUtil.isJsonValid(decodedDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid JSON.");
			throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
					SignatureErrorCode.INVALID_JSON.getErrorMessage());
		}

		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String applicationId = jwtSignRequestDto.getApplicationId();
		String referenceId = jwtSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludePayload());
		boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertificate());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
				jwtSignRequestDto.getCertificateUrl()) ? jwtSignRequestDto.getCertificateUrl(): null;

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(timestamp));
		String signedData = sign(decodedDataToSign, certificateResponse, includePayload, includeCertificate,
				includeCertHash, certificateUrl, referenceId);
		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData);
		responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request - Completed");

		return responseDto;
	}

	private String sign(String dataToSign, SignatureCertificate certificateResponse, boolean includePayload,
						boolean includeCertificate, boolean includeCertHash, String certificateUrl, String referenceId) {

		JsonWebSignature jwSign = new JsonWebSignature();
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		if (includeCertificate)
			jwSign.setCertificateChainHeaderValue(new X509Certificate[] { x509Certificate });

		if (includeCertHash)
			jwSign.setX509CertSha256ThumbprintHeaderValue(x509Certificate);

		if (Objects.nonNull(certificateUrl))
			jwSign.setHeader("x5u", certificateUrl);

		String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());
		if (includeKeyId && Objects.nonNull(keyId))
			jwSign.setKeyIdHeaderValue(keyId);

		jwSign.setPayload(dataToSign);
		String algoString = JWT_SIGNATURE_ALGO_IDENT.get(referenceId);
		if (!KeyReferenceIdConsts.ED25519_SIGN.name().equals(referenceId)) {
			ProviderContext provContext = new ProviderContext();
			provContext.getSuppliedKeyProviderContext().setSignatureProvider(ecKeyStore.getKeystoreProviderName());
			jwSign.setProviderContext(provContext);
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Supported Signature Algorithm: " +
						AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().getSupportedAlgorithms());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Signature Algorithm for the input RefId: " + algoString);

		jwSign.setAlgorithmHeaderValue(algoString);
		jwSign.setKey(privateKey);
		jwSign.setDoKeyValidation(false);

		try {
			if (includePayload)
				return jwSign.getCompactSerialization();

			return jwSign.getDetachedContentCompactSerialization();
		} catch (JoseException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Error occurred while Signing Data.", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
					SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	public JWTSignatureVerifyResponseDto jwtVerify(JWTSignatureVerifyRequestDto jwtVerifyRequestDto) {

		String signedData = jwtVerifyRequestDto.getJwtSignatureData();
		if (!SignatureUtil.isDataValid(signedData)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		String encodedActualData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getActualData())
				? jwtVerifyRequestDto.getActualData() : null;

		String reqCertData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getCertificateData())
				? jwtVerifyRequestDto.getCertificateData(): null;
		String applicationId = jwtVerifyRequestDto.getApplicationId();
		String referenceId = jwtVerifyRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		String[] jwtTokens = signedData.split(SignatureConstant.PERIOD, -1);

		boolean signatureValid = false;
		Certificate certToVerify = certificateExistsInHeader(jwtTokens[0]);
		if (Objects.nonNull(certToVerify)){
			signatureValid = verifySignature(jwtTokens, encodedActualData, certToVerify);
		} else {
			Certificate reqCertToVerify = getCertificateToVerify(reqCertData, applicationId, referenceId);
			signatureValid = verifySignature(jwtTokens, encodedActualData, reqCertToVerify);
		}

		JWTSignatureVerifyResponseDto responseDto = new JWTSignatureVerifyResponseDto();
		responseDto.setSignatureValid(signatureValid);
		responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
		responseDto.setTrustValid(validateTrust(jwtVerifyRequestDto, certToVerify, reqCertData));
		return responseDto;
	}

	private Certificate getCertificateToVerify(String reqCertData, String applicationId, String referenceId) {
		// 2nd precedence to consider certificate to use in signature verification (Certificate Data provided in request).
		if (reqCertData != null)
			return keymanagerUtil.convertToCertificate(reqCertData);

		// 3rd precedence to consider certificate to use in signature verification. (based on AppId & RefId)
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		return certificateResponse.getCertificateEntry().getChain()[0];
	}

	private Certificate certificateExistsInHeader(String jwtHeader) {
		String jwtTokenHeader = new String(CryptoUtil.decodeBase64(jwtHeader));
		Map<String, Object> jwtTokenHeadersMap = null;
		try {
			jwtTokenHeadersMap = JsonUtils.jsonStringToJavaMap(jwtTokenHeader);
		} catch (JsonParseException | JsonMappingException | io.mosip.kernel.core.exception.IOException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
		}
		// 1st precedence to consider certificate to use in signature verification (JWT Header).
		if (jwtTokenHeadersMap.containsKey(SignatureConstant.JWT_HEADER_CERT_KEY)) {
			LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Certificate found in JWT Header.");
			List<String> certList = (List<String>) jwtTokenHeadersMap.get(SignatureConstant.JWT_HEADER_CERT_KEY);
			return keymanagerUtil.convertToCertificate(Base64.decodeBase64(certList.get(0)));
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Certificate not found in JWT Header.");
		return null;
	}

	private boolean verifySignature(String[] jwtTokens, String actualData, Certificate certToVerify) {
		JsonWebSignature jws = new JsonWebSignature();
		try {
			X509Certificate x509CertToVerify = (X509Certificate) certToVerify;
			boolean validCert = SignatureUtil.isCertificateDatesValid(x509CertToVerify);
			if (!validCert) {
				LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
						"Error certificate dates are not valid.");
				throw new CertificateNotValidException(SignatureErrorCode.CERT_NOT_VALID.getErrorCode(),
						SignatureErrorCode.CERT_NOT_VALID.getErrorMessage());
			}

			String keyAlgorithm = x509CertToVerify.getPublicKey().getAlgorithm();
			PublicKey publicKey = null;
			if (keyAlgorithm.equals(KeymanagerConstant.EDDSA_KEY_TYPE)) {
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
						"Found Ed25519 Certificate for Signature verification.");
				publicKey = KeyGeneratorUtils.createPublicKey(KeymanagerConstant.ED25519_KEY_TYPE,
						x509CertToVerify.getPublicKey().getEncoded());
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
						"Supported Signature Algorithm: " +
								AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().getSupportedAlgorithms());
			} else {
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
						"KeyStore Provider Name:" + ecKeyStore.getKeystoreProviderName());
				if (!ecKeyStore.getKeystoreProviderName().equals(
						io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant.KEYSTORE_TYPE_OFFLINE)) {
					ProviderContext provContext = new ProviderContext();
					provContext.getSuppliedKeyProviderContext().setSignatureProvider(ecKeyStore.getKeystoreProviderName());
					jws.setProviderContext(provContext);
				}
				publicKey = certToVerify.getPublicKey();
			}

			if (Objects.nonNull(actualData))
				jwtTokens[1] = actualData;

			jws.setCompactSerialization(CompactSerializer.serialize(jwtTokens));
			jws.setDoKeyValidation(false);
			if (Objects.nonNull(publicKey))
				jws.setKey(publicKey);

			return jws.verifySignature();
		} catch (JoseException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.", e);
			throw new SignatureFailureException(SignatureErrorCode.VERIFY_ERROR.getErrorCode(),
					SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
		}
	}

	// private boolean verifySignature(String[] jwtTokens, String actualData, PublicKey publicKey) {
	// 	JsonWebSignature jws = new JsonWebSignature();
	// 	try {
	// 		if (Objects.nonNull(actualData))
	// 			jwtTokens[1] = actualData;

	// 		jws.setCompactSerialization(CompactSerializer.serialize(jwtTokens));
	// 		if (Objects.nonNull(publicKey))
	// 			jws.setKey(publicKey);

	// 		return jws.verifySignature();
	// 	} catch (ArrayIndexOutOfBoundsException | JoseException e) {
	// 		LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
	// 				"Provided Signed Data value is invalid.");
	// 		throw new SignatureFailureException(SignatureErrorCode.VERIFY_ERROR.getErrorCode(),
	// 								SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
	// 	}
	// }

	private String validateTrust(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, Certificate headerCertificate, String reqCertData) {

		boolean validateTrust = SignatureUtil.isIncludeAttrsValid(jwtVerifyRequestDto.getValidateTrust());
		if (!validateTrust) {
			return SignatureConstant.TRUST_NOT_VERIFIED;
		}

		String domain = jwtVerifyRequestDto.getDomain();
		if(!SignatureUtil.isDataValid(domain))
			return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;

		String certData = null;
		if (Objects.nonNull(headerCertificate)) {
			certData = keymanagerUtil.getPEMFormatedData(headerCertificate);
		}
		String trustCertData = certData == null ? reqCertData : certData;

		if (trustCertData == null)
			return SignatureConstant.TRUST_NOT_VERIFIED;

		CertificateTrustRequestDto trustRequestDto = new CertificateTrustRequestDto();
		trustRequestDto.setCertificateData(trustCertData);
		trustRequestDto.setPartnerDomain(domain);
		CertificateTrustResponeDto responseDto = partnerCertManagerService.verifyCertificateTrust(trustRequestDto);

		if (responseDto.getStatus()){
			return SignatureConstant.TRUST_VALID;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation - Completed.");
		return SignatureConstant.TRUST_NOT_VALID;
	}
	// @Override
	// public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto) {
	// 	// TODO Code is duplicated from jwtSign method. Duplicate code will be removed later when VC verification is implementation.
	// 	// Code duplicated because now does not want to make any change to existing code which is well tested.
	// 	LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
	// 			"JWS Signature Request.");

	// 	String reqDataToSign = jwsSignRequestDto.getDataToSign();
	// 	if (!SignatureUtil.isDataValid(reqDataToSign)) {
	// 		LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
	// 				"Provided Data to sign value is invalid.");
	// 		throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
	// 				SignatureErrorCode.INVALID_INPUT.getErrorMessage());
	// 	}

	// 	Boolean validateJson = jwsSignRequestDto.getValidateJson();
	// 	byte[] dataToSign = CryptoUtil.decodeBase64(reqDataToSign);
	// 	if (validateJson && !SignatureUtil.isJsonValid(new String(dataToSign))) {
	// 		LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
	// 				"Provided Data to sign value is invalid JSON.");
	// 		throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
	// 				SignatureErrorCode.INVALID_JSON.getErrorMessage());
	// 	}

	// 	String timestamp = DateUtils.getUTCCurrentDateTimeString();
	// 	String applicationId = jwsSignRequestDto.getApplicationId();
	// 	String referenceId = jwsSignRequestDto.getReferenceId();
	// 	if (!keymanagerUtil.isValidApplicationId(applicationId)) {
	// 		applicationId = signApplicationid;
	// 		referenceId = signRefid;
	// 	}

	// 	boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
	// 	boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificate());
	// 	boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
	// 	String certificateUrl = SignatureUtil.isDataValid(
	// 							jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;
	// 	boolean b64JWSHeaderParam = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getB64JWSHeaderParam());
	// 	String signAlgorithm = SignatureUtil.isDataValid(jwsSignRequestDto.getSignAlgorithm()) ?
	// 								jwsSignRequestDto.getSignAlgorithm(): SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;

	// 	SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
	// 								Optional.of(referenceId), timestamp);
	// 	keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
	// 								DateUtils.parseUTCToDate(timestamp));
	// 	PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
	// 	X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
	// 	String providerName = certificateResponse.getProviderName();
	// 	String uniqueIdentifier = certificateResponse.getUniqueIdentifier();
	// 	JWSHeader jwsHeader = SignatureUtil.getJWSHeader(signAlgorithm, b64JWSHeaderParam, includeCertificate,
	// 	includeCertHash, certificateUrl, x509Certificate, uniqueIdentifier, includeKeyId);

	// 	if (b64JWSHeaderParam) {
	// 		dataToSign = reqDataToSign.getBytes(StandardCharsets.UTF_8);
	// 	}
	// 	byte[] jwsSignData = SignatureUtil.buildSignData(jwsHeader, dataToSign);

	// 	SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
	// 	if (Objects.isNull(signatureProvider)) {
	// 		signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
	// 	}

	// 	String signature = signatureProvider.sign(privateKey, jwsSignData, providerName);

	// 	StringBuilder signedData = new StringBuilder().append(jwsHeader.toBase64URL().toString())
	// 													 .append(".")
	// 													 .append(includePayload? reqDataToSign: "")
	// 													 .append(".")
	// 													 .append(signature);

	// 	JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
	// 	responseDto.setJwtSignedData(signedData.toString());
	// 	responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
	// 	if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name())) {
	// 		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
	// 			"Found Ed25519 Key for Signature, clearing the Key from memory.");
	// 		privateKey = null;
	// 	}
	// 	LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
	// 			"JWS Signature Request - Completed.");
	// 	return responseDto;
	// }

	@Override
	public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto) {
		// TODO Code is duplicated from jwtSign method. Duplicate code will be removed later when VC verification is implement.
		// Code duplicated because now does not want to make any change to existing code which is well tested.
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
				"JWS Signature Request.");

		// boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(jwsSignRequestDto.getApplicationId());
		// if (!hasAcccess) {
		// 	LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
		// 					"Signing Data is not allowed for the authenticated user for the provided application id.");
		// 	throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
		// 		SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		// }

		String reqDataToSign = jwsSignRequestDto.getDataToSign();
		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		Boolean validateJson = jwsSignRequestDto.getValidateJson();
		byte[] dataToSign = CryptoUtil.decodeBase64(reqDataToSign);
		if (validateJson && !SignatureUtil.isJsonValid(new String(dataToSign))) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign value is invalid JSON.");
			throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
					SignatureErrorCode.INVALID_JSON.getErrorMessage());
		}

		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String applicationId = jwsSignRequestDto.getApplicationId();
		String referenceId = jwsSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
		boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificate());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
				jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;
		boolean b64JWSHeaderParam = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getB64JWSHeaderParam());
		String signAlgorithm = SignatureUtil.isDataValid(jwsSignRequestDto.getSignAlgorithm()) ?
				jwsSignRequestDto.getSignAlgorithm(): SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		String providerName = certificateResponse.getProviderName();
		String uniqueIdentifier = certificateResponse.getUniqueIdentifier();
		JWSHeader jwsHeader = SignatureUtil.getJWSHeader(signAlgorithm, b64JWSHeaderParam, includeCertificate,
				includeCertHash, certificateUrl, x509Certificate, uniqueIdentifier, includeKeyId);

		if (b64JWSHeaderParam) {
			dataToSign = reqDataToSign.getBytes(StandardCharsets.UTF_8);
		}
		byte[] jwsSignData = SignatureUtil.buildSignData(jwsHeader, dataToSign);

		SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
		if (Objects.isNull(signatureProvider)) {
			signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
		}

		String signature = signatureProvider.sign(privateKey, jwsSignData, providerName);

		StringBuilder signedData = new StringBuilder().append(jwsHeader.toBase64URL().toString())
				.append(".")
				.append(includePayload? reqDataToSign: "")
				.append(".")
				.append(signature);

		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData.toString());
		responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name())) {
			LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Found Ed25519 Key for Signature, clearing the Key from memory.");
			privateKey = null;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
				"JWS Signature Request - Completed.");
		return responseDto;
	}

	@Override
	public COSESign1ResponseDto coseSign1(COSESign1RequestDto coseSign1RequestDto) {
		COSESign1ResponseDto responseDto = new COSESign1ResponseDto();
		try {
			String reqDataToSign = coseSign1RequestDto.getDataToSign();
			if (!SignatureUtil.isDataValid(reqDataToSign)) {
				LOGGER.error(SignatureConstant.SESSIONID, "COSE_SIGN1", SignatureConstant.BLANK,
						"Provided Data to sign is invalid.");
				throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
						SignatureErrorCode.INVALID_INPUT.getErrorMessage());
			}
			String decodedDataToSign = new String(Base64.decodeBase64(reqDataToSign));
			String timestamp = DateUtils.getUTCCurrentDateTimeString();
			String applicationId = coseSign1RequestDto.getApplicationId();
			String referenceId = coseSign1RequestDto.getReferenceId();
			if (!keymanagerUtil.isValidApplicationId(applicationId)) {
				applicationId = signApplicationid;
				referenceId = signRefid;
			}
			SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
					Optional.of(referenceId), timestamp);
			keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
					DateUtils.parseUTCToDate(timestamp));
			ECPrivateKey privateKey = (ECPrivateKey) certificateResponse.getCertificateEntry().getPrivateKey();
			byte[] payloadBytes = COSESign1Util.jsonToBytes(reqDataToSign);
			String coseSign1 = COSESign1Util.sign(payloadBytes, privateKey);
			responseDto.setCoseSign1Data(coseSign1);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
		} catch (Exception e) {
			LOGGER.error(SignatureConstant.SESSIONID, "COSE_SIGN1", SignatureConstant.BLANK,
					"Error occurred while Signing Data.", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
					SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
		return responseDto;
	}

	@Override
	public COSESign1VerifyResponseDto coseVerify1(COSESign1VerifyRequestDto coseSign1VerifyRequestDto) {
		COSESign1VerifyResponseDto responseDto = new COSESign1VerifyResponseDto();
		try {
			String signedData = coseSign1VerifyRequestDto.getCoseSign1Data();
			if (!SignatureUtil.isDataValid(signedData)) {
				LOGGER.error(SignatureConstant.SESSIONID, "COSE_SIGN1", SignatureConstant.BLANK,
						"Provided Signed Data value is invalid.");
				throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
						SignatureErrorCode.INVALID_INPUT.getErrorMessage());
			}
			String actualData = coseSign1VerifyRequestDto.getActualData();
			byte[] expectedPayload = COSESign1Util.jsonToBytes(actualData);
			String applicationId = coseSign1VerifyRequestDto.getApplicationId();
			String referenceId = coseSign1VerifyRequestDto.getReferenceId();
			if (!keymanagerUtil.isValidApplicationId(applicationId)) {
				applicationId = signApplicationid;
				referenceId = signRefid;
			}
			SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
					Optional.of(referenceId), DateUtils.getUTCCurrentDateTimeString());
			keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
					DateUtils.parseUTCToDate(DateUtils.getUTCCurrentDateTimeString()));
			ECPublicKey publicKey = (ECPublicKey) certificateResponse.getCertificateEntry().getChain()[0].getPublicKey();
			boolean valid = COSESign1Util.verify(Base64.decodeBase64(signedData), publicKey, expectedPayload);
			responseDto.setSignatureValid(valid);
			responseDto.setMessage(valid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
			// Trust validation can be extended as needed
			responseDto.setTrustValid(valid);
		} catch (Exception e) {
			LOGGER.error(SignatureConstant.SESSIONID, "COSE_SIGN1", SignatureConstant.BLANK,
					"Error occurred while Verifying Data.", e);
			responseDto.setSignatureValid(false);
			responseDto.setMessage(SignatureConstant.VALIDATION_FAILED);
			responseDto.setTrustValid(false);
		}
		return responseDto;
	}

	@Override
	public SignResponseDto signv2(SignRequestDtoV2 signatureReq) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
				"Raw Sign Signature Request.");
		String applicationId = signatureReq.getApplicationId();
		String referenceId = signatureReq.getReferenceId();
		boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(applicationId);
		String reqDataToSign = signatureReq.getDataToSign();
		if (!hasAcccess) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
					"Signing Data is not allowed for the authenticated user for the provided application id.");
			throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
					SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		}

		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}
		byte[] dataToSign = CryptoUtil.decodeBase64(reqDataToSign);
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}
		String signAlgorithm = SignatureUtil.isDataValid(signatureReq.getSignAlgorithm()) ?
				signatureReq.getSignAlgorithm(): SignatureConstant.ED25519_ALGORITHM;

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		certificateResponse.getCertificateEntry().getChain();
		String providerName = certificateResponse.getProviderName();
		SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
		if (Objects.isNull(signatureProvider)) {
			signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
		}
		String signature = signatureProvider.sign(privateKey, dataToSign, providerName);
		byte[] data = java.util.Base64.getUrlDecoder().decode(signature);
		SignResponseDto signedData = new SignResponseDto();
		signedData.setTimestamp(DateUtils.getUTCCurrentDateTime());
		switch (signatureReq.getResponseEncodingFormat()) {
			case "base64url":
				signedData.setSignature(Multibase.encode(Multibase.Base.Base64Url, data));
				break;
			case "base58btc":
				signedData.setSignature(Multibase.encode(Multibase.Base.Base58BTC, data));
				break;
			default:
				throw new InvalidFormatException(KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorCode(),
						KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorMessage());
		}
		return signedData;
	}

	@Override
	public CBORSignatureResponseDto cborSign(CBORSignatureRequestDto cborSignRequestDto) {
		CBORSignatureResponseDto responseDto = new CBORSignatureResponseDto();
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String sessionId = SignatureConstant.SESSIONID;
		
		LOGGER.info(sessionId, "CBOR_SIGN", SignatureConstant.BLANK, 
				"Starting CBOR signing process. ApplicationId: {}, ReferenceId: {}", 
				cborSignRequestDto.getApplicationId(), cborSignRequestDto.getReferenceId());
		
		try {
			// Validate input data
			if (!SignatureUtil.isDataValid(cborSignRequestDto.getDataToSign())) {
				LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
						"Invalid dataToSign provided. Data is null or empty.");
				throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
						SignatureErrorCode.INVALID_INPUT.getErrorMessage());
			}
			
			LOGGER.debug(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"Input dataToSign length: {} characters", cborSignRequestDto.getDataToSign().length());
			
			// Check if hex string has even length
			if (cborSignRequestDto.getDataToSign().length() % 2 != 0) {
				LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
						"Invalid hex string: odd number of characters. Length: {}", 
						cborSignRequestDto.getDataToSign().length());
				throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
						"Invalid hex string: odd number of characters");
			}
			
			String signedHex = cborSignInternal(cborSignRequestDto.getDataToSign(), 
					cborSignRequestDto.getApplicationId(), 
					cborSignRequestDto.getReferenceId(), 
					timestamp);
			
			responseDto.setCborSignedData(signedHex);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
			
			LOGGER.info(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"CBOR signing completed successfully. Output length: {} characters", 
					signedHex != null ? signedHex.length() : 0);
			
		} catch (DecoderException e) {
			LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"Hex decoding error: {}", e.getMessage(), e);
			responseDto.setCborSignedData(null);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
		} catch (CBORMalformedUtf8Exception e) {
			LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"CBOR UTF-8 error at offset {}: {}. This indicates binary data was encoded as text string.", 
					e.getOffset(), e.getMessage(), e);
			try {
				LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
						"Problematic bytes around offset {}: {}", e.getOffset(), 
						getHexBytesAroundOffset(Hex.decodeHex(cborSignRequestDto.getDataToSign().toCharArray()), e.getOffset()));
			} catch (DecoderException hexException) {
				LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
						"Failed to decode hex for byte analysis: {}", hexException.getMessage());
			}
			responseDto.setCborSignedData(null);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
		} catch (CBORInsufficientDataException e) {
			LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"CBOR insufficient data: {}. Input may be truncated.", e.getMessage(), e);
			responseDto.setCborSignedData(null);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
		} catch (Exception e) {
			LOGGER.error(sessionId, "CBOR_SIGN", SignatureConstant.BLANK,
					"Unexpected error during CBOR signing: {}", e.getMessage(), e);
			responseDto.setCborSignedData(null);
			responseDto.setTimestamp(DateUtils.getUTCCurrentDateTimeString());
		}
		return responseDto;
	}

	@Override
	public CBORSignatureVerifyResponseDto cborVerify(CBORSignatureVerifyRequestDto cborSignatureVerifyRequestDto) {
		CBORSignatureVerifyResponseDto responseDto = new CBORSignatureVerifyResponseDto();
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String sessionId = SignatureConstant.SESSIONID;
		
		LOGGER.info(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK, 
				"Starting CBOR verification process. ApplicationId: {}, ReferenceId: {}", 
				cborSignatureVerifyRequestDto.getApplicationId(), cborSignatureVerifyRequestDto.getReferenceId());
		
		try {
			if (!SignatureUtil.isDataValid(cborSignatureVerifyRequestDto.getCborSignatureData())) {
				LOGGER.error(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK,
						"Invalid cborSignatureData provided. Data is null or empty.");
				throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
						SignatureErrorCode.INVALID_INPUT.getErrorMessage());
			}
			
			boolean valid = cborVerifyInternal(cborSignatureVerifyRequestDto.getCborSignatureData(), 
					cborSignatureVerifyRequestDto.getApplicationId(), 
					cborSignatureVerifyRequestDto.getReferenceId(), 
					timestamp);
			
			responseDto.setSignatureValid(valid);
			responseDto.setMessage(valid ? "Validation successful" : "Validation failed");
			
			// Trust validation - use the same approach as JWT
			String trustResult = validateCborTrust(cborSignatureVerifyRequestDto, null, null);
			responseDto.setTrustValid(SignatureConstant.TRUST_VALID.equals(trustResult));
			
			LOGGER.info(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK,
					"CBOR verification completed. Result: {}, Trust: {}", valid ? "VALID" : "INVALID", trustResult);
			
		} catch (DecoderException e) {
			LOGGER.error(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK,
					"Hex decoding error during verification: {}", e.getMessage(), e);
			responseDto.setSignatureValid(false);
			responseDto.setMessage("Hex decoding error: " + e.getMessage());
			responseDto.setTrustValid(false);
		} catch (CBORMalformedUtf8Exception e) {
			LOGGER.error(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK,
					"CBOR UTF-8 error during verification at offset {}: {}", e.getOffset(), e.getMessage(), e);
			responseDto.setSignatureValid(false);
			responseDto.setMessage("CBOR UTF-8 error: " + e.getMessage());
			responseDto.setTrustValid(false);
		} catch (Exception e) {
			LOGGER.error(sessionId, "CBOR_VERIFY", SignatureConstant.BLANK,
					"Unexpected error during CBOR verification: {}", e.getMessage(), e);
			responseDto.setSignatureValid(false);
			responseDto.setMessage("Exception: " + e.getMessage());
			responseDto.setTrustValid(false);
		}
		return responseDto;
	}

	// --- CBOR/CWT core logic (simplified, adapt as needed) ---
	private static final int CLAIM_169 = 169;
	private static final String ISS = "www.mosip.io";
	private String cborSignInternal(String claim169Data, String applicationId, String referenceId, String timestamp) throws Exception {
		String sessionId = SignatureConstant.SESSIONID;
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Processing CBOR signing with applicationId: {}, referenceId: {}", applicationId, referenceId);
		
		// Fallback logic as in JWT
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			LOGGER.warn(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Invalid applicationId: {}. Using default: {}", applicationId, signApplicationid);
			applicationId = signApplicationid;
			referenceId = signRefid;
		}
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Getting signature certificate for applicationId: {}, referenceId: {}", applicationId, referenceId);
		
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), DateUtils.parseUTCToDate(timestamp));
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Certificate validation successful. KeyId: {}", certificateResponse.getUniqueIdentifier());
		
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		String keyId = certificateResponse.getUniqueIdentifier();
		int algorithm = COSEAlgorithms.ES256;
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Using algorithm: {}, keyId: {}", algorithm, keyId);
		
		COSEProtectedHeader protectedHeader = new COSEProtectedHeaderBuilder().alg(algorithm).build();
		COSEUnprotectedHeader unprotectedHeader = new COSEUnprotectedHeaderBuilder().kid(keyId).build();
		long currentTime = Instant.now().getEpochSecond();
		long expireTime = currentTime + 365L * 24 * 60 * 60; // 1 year expiry
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Decoding hex string to bytes. Input length: {}", claim169Data.length());
		
		byte[] claim169Bytes;
		try {
			claim169Bytes = Hex.decodeHex(claim169Data.toCharArray());
			LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Hex decoding successful. Decoded bytes length: {}", claim169Bytes.length);
		} catch (DecoderException e) {
			LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Failed to decode hex string: {}. Input: {}", e.getMessage(), 
					claim169Data.length() > 100 ? claim169Data.substring(0, 100) + "..." : claim169Data);
			throw new RuntimeException("Invalid hex string for claim169Data", e);
		}
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Starting CBOR decoding of claim169 data");
		
		CBORItem item;
		try {
			item = new CBORDecoder(claim169Bytes).next();
			LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"CBOR decoding successful. Item type: {}", item.getClass().getSimpleName());
		} catch (CBORMalformedUtf8Exception e) {
			LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"CBOR UTF-8 error at offset {}: {}. This indicates binary data was encoded as text string.", 
					e.getOffset(), e.getMessage());
			LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Problematic bytes around offset {}: {}", e.getOffset(), 
					getHexBytesAroundOffset(Hex.decodeHex(claim169Data.toCharArray()), e.getOffset()));
			throw e;
		} catch (CBORInsufficientDataException e) {
			LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"CBOR insufficient data: {}. Input may be truncated.", e.getMessage());
			throw e;
		} catch (Exception e) {
			LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"CBOR decoding error: {}", e.getMessage(), e);
			throw e;
		}
		
		CBORPairList pairList = (CBORPairList) item;
		Map<Object, Object> claim169Map = pairList.parse();
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"CBOR map parsed successfully. Map size: {}", claim169Map.size());
		
		// Process photo data if present
		for (Object key : claim169Map.keySet()) {
			if (((Integer) key) == 62) {
				LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
						"Found photo data (key 62), processing...");
				Map<Object, Object> photoDataMap = (Map) claim169Map.get(key);
				String photoData = (String) photoDataMap.get(Integer.valueOf(0));
				
				LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
						"Photo data hex length: {}", photoData != null ? photoData.length() : 0);
				
				byte[] photoBytes;
				try {
					photoBytes = Hex.decodeHex(photoData.toCharArray());
					LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Photo data hex decoding successful. Decoded bytes: {}", photoBytes.length);
				} catch (DecoderException e) {
					LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Failed to decode photo data hex string: {}", e.getMessage());
					throw new RuntimeException("Invalid hex string for photoData", e);
				}
				photoDataMap.put(0, photoBytes);
				claim169Map.put(62, photoDataMap);
				break;
			}
		}
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Creating updated CBOR structure");
		
		CBORPairList updatedPairList = (CBORPairList) new CBORizer().cborizeMap(claim169Map);
		byte[] claim169Bts = updatedPairList.encode();
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Updated CBOR structure encoded. Size: {} bytes", claim169Bts.length);
		
		CWTClaimsSet claimsSet = new CWTClaimsSetBuilder()
				.iss(ISS)
				.exp(expireTime)
				.nbf(currentTime)
				.iat(currentTime)
				.put(CLAIM_169, claim169Bts)
				.build();
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"CWT claims set created. Issuer: {}, Expiry: {}", ISS, expireTime);
		
		CBORByteArray claim169Payload = new CBORByteArray(claimsSet.encode());
		SigStructure sigStructure = new SigStructureBuilder().signature1()
				.bodyAttributes(protectedHeader)
				.payload(claim169Payload)
				.build();
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Signature structure created. Starting signing process");
		
		// CURRENT: Simplified approach following JWT signing pattern (NOT WORKING with HSM)
		/*
		// Use the same approach as JWT signing with EC keys
		COSESigner signer = new COSESigner(privateKey);
		
		// Set provider context like JWT signing does
		if (!ecKeyStore.getKeystoreProviderName().equals(
				io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant.KEYSTORE_TYPE_OFFLINE)) {
			ProviderContext provContext = new ProviderContext();
			provContext.getSuppliedKeyProviderContext().setSignatureProvider(ecKeyStore.getKeystoreProviderName());
			// Note: COSESigner doesn't have setProviderContext method, so we rely on the key's provider
		}
		
		byte[] signature = signer.sign(sigStructure, algorithm);
		*/
		
		// BACKUP: Original complex fallback approach (WORKING with HSM)
		byte[] signature;
		String providerName = ecKeyStore.getKeystoreProviderName();
		boolean usedAlternativeSigning = false;
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Using provider: {} for signing", providerName);
		
		try {
			// Try using COSESigner with generic PrivateKey first
			COSESigner signer = new COSESigner(privateKey);
			signature = signer.sign(sigStructure, algorithm);
			if (signature.length != 64) { // 64 bytes for P-256
				signature = derToRaw(signature, 32);
			}
			LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Direct COSE signing successful with provider: {}", providerName);
		} catch (Exception e) {
			LOGGER.warn(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"Direct COSE signing failed with provider {}, trying alternative approach: {}", 
					providerName, e.getMessage());
			
			// Alternative: Use Java's Signature class with provider-specific configuration
			try {
				java.security.Signature sig;
				if (providerName != null && providerName.toLowerCase().contains("pkcs11")) {
					// PKCS#11 provider (SoftHSM2) - use default provider for better compatibility
					sig = java.security.Signature.getInstance("SHA256withECDSA");
					LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Using default provider for PKCS#11 (SoftHSM2) signing");
				} else if (providerName != null && providerName.toLowerCase().contains("luna")) {
					// Luna HSM - try multiple approaches due to sensitive attributes issue
					LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Luna HSM detected, trying multiple signing approaches");
					
					// Try with Luna provider first
					try {
						sig = java.security.Signature.getInstance("SHA256withECDSA", providerName);
						LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
								"Using Luna provider for signing");
					} catch (Exception lunaException) {
						LOGGER.warn(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
								"Luna provider failed: {}, trying default provider", lunaException.getMessage());
						// Fallback to default provider for Luna
						sig = java.security.Signature.getInstance("SHA256withECDSA");
					}
				} else if (providerName != null && providerName.toLowerCase().contains("jce")) {
					// JCE provider (Luna HSM) - use the specific provider
					sig = java.security.Signature.getInstance("SHA256withECDSA", providerName);
					LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Using JCE provider (Luna HSM) for signing");
				} else {
					// Other providers - use default
					sig = java.security.Signature.getInstance("SHA256withECDSA");
					LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
							"Using default provider for signing");
				}
				
				sig.initSign(privateKey);
				sig.update(sigStructure.encode());
				signature = sig.sign();
				if (signature.length != 64) { // 64 bytes for P-256
					signature = derToRaw(signature, 32);
				}
				usedAlternativeSigning = true;
				
				LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
						"Alternative signing successful with provider: {}, algorithm: {}, signature length: {} bytes", 
						providerName, sig.getAlgorithm(), signature.length);
			} catch (Exception altException) {
				LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
						"Both signing approaches failed with provider {}. Original: {}, Alternative: {}", 
						providerName, e.getMessage(), altException.getMessage());
				
				// For Luna HSM, try one more approach with different algorithm
				if (providerName != null && (providerName.toLowerCase().contains("luna") || 
					altException.getMessage().contains("Cannot access sensitive attributes"))) {
					try {
						LOGGER.warn(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
								"Trying ECDSA without SHA256 for Luna HSM compatibility");
						java.security.Signature sig = java.security.Signature.getInstance("ECDSA");
						sig.initSign(privateKey);
						sig.update(sigStructure.encode());
						signature = sig.sign();
						if (signature.length != 64) { // 64 bytes for P-256
							signature = derToRaw(signature, 32);
						}
						usedAlternativeSigning = true;
						
						LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
								"ECDSA signing successful for Luna HSM");
					} catch (Exception ecdsaException) {
						LOGGER.error(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
								"All Luna HSM signing approaches failed. ECDSA: {}", ecdsaException.getMessage());
						throw new RuntimeException("Failed to sign with Luna HSM key (provider: " + providerName + ")", ecdsaException);
					}
				} else {
					throw new RuntimeException("Failed to sign with HSM key (provider: " + providerName + ")", altException);
				}
			}
		}
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"CBOR signing completed. Signature length: {} bytes, Used alternative signing: {}", 
				signature.length, usedAlternativeSigning);
		
		// Log the signing approach for debugging verification issues
		if (usedAlternativeSigning) {
			LOGGER.warn(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
					"SIGNATURE CREATED WITH ALTERNATIVE APPROACH (Java Signature class) - " +
					"This may cause verification issues with COSEVerifier");
		}
		
		COSESign1 sign1 = new COSESign1Builder()
				.protectedHeader(protectedHeader)
				.unprotectedHeader(unprotectedHeader)
				.payload(claim169Payload)
				.signature(signature)
				.build();
		
		CWT cwt = new CWT(sign1);
		String result = cwt.encodeToHex();
		
		LOGGER.debug(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"CBOR signing completed. Final hex length: {}", result.length());
		
		LOGGER.info(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Signature hex: {}", org.apache.commons.codec.binary.Hex.encodeHexString(signature));
		LOGGER.info(sessionId, "CBOR_SIGN_INTERNAL", SignatureConstant.BLANK,
				"Signature length: {}", signature.length);
		
		return result;
	}

	private boolean cborVerifyInternal(String cwtSignedData, String applicationId, String referenceId, String timestamp) throws Exception {
		String sessionId = SignatureConstant.SESSIONID;
		
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Processing CBOR verification with applicationId: {}, referenceId: {}", applicationId, referenceId);
		
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			LOGGER.warn(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
					"Invalid applicationId: {}. Using default: {}", applicationId, signApplicationid);
			applicationId = signApplicationid;
			referenceId = signRefid;
		}
		
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), DateUtils.parseUTCToDate(timestamp));
		X509Certificate cert = certificateResponse.getCertificateEntry().getChain()[0];
		PublicKey publicKey = cert.getPublicKey(); // Use generic PublicKey like JWT verification
		String providerName = certificateResponse.getProviderName();
		
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Certificate retrieved and validated. Provider: {}, Key algorithm: {}", 
				providerName, publicKey.getAlgorithm());
		
		byte[] encodedCWT = Hex.decodeHex(cwtSignedData.toCharArray());
		
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"CWT hex decoded. Length: {} bytes", encodedCWT.length);
		
		CWT cwt = (CWT) new CBORDecoder(encodedCWT).next();
		COSEMessage message = cwt.getMessage();
		COSESign1 sign1 = (COSESign1) message;
		
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"CWT decoded successfully. Starting signature verification");
		
		// Log signature details for debugging
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Signature details - Algorithm: {}", sign1.getProtectedHeader().getAlg());
		
		boolean valid = false;
		
		// Try direct COSE verification
		try {
			LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
					"Attempting COSE verification with provider: {}, public key algorithm: {}", 
					providerName, publicKey.getAlgorithm());
			
			COSEVerifier verifier = new COSEVerifier(publicKey);
			valid = verifier.verify(sign1);
			LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
					"Direct COSE verification result: {}", valid);
		} catch (Exception e) {
			LOGGER.warn(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
					"Direct COSE verification failed with provider {}, trying alternative approach: {}", 
					providerName, e.getMessage());
			
			// Alternative: Use Java's Signature class with provider-specific configuration
			try {
				java.security.Signature sig;
				if (providerName != null && providerName.toLowerCase().contains("pkcs11")) {
					// PKCS#11 provider (SoftHSM2) - use default provider for better compatibility
					sig = java.security.Signature.getInstance("SHA256withECDSA");
					LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
							"Using default provider for PKCS#11 (SoftHSM2) verification");
				} else if (providerName != null && providerName.toLowerCase().contains("luna")) {
					// Luna HSM - try multiple approaches due to sensitive attributes issue
					LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
							"Luna HSM detected, trying multiple verification approaches");
					
					// Try with Luna provider first
					try {
						sig = java.security.Signature.getInstance("SHA256withECDSA", providerName);
						LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
								"Using Luna provider for verification");
					} catch (Exception lunaException) {
						LOGGER.warn(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
								"Luna provider failed: {}, trying default provider", lunaException.getMessage());
						// Fallback to default provider for Luna
						sig = java.security.Signature.getInstance("SHA256withECDSA");
					}
				} else if (providerName != null && providerName.toLowerCase().contains("jce")) {
					// JCE provider (Luna HSM) - use the specific provider
					sig = java.security.Signature.getInstance("SHA256withECDSA", providerName);
					LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
							"Using JCE provider (Luna HSM) for verification");
				} else {
					// Other providers - use default
					sig = java.security.Signature.getInstance("SHA256withECDSA");
					LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
							"Using default provider for verification");
				}
				
				// Reconstruct the signature structure for verification
				COSEProtectedHeader protectedHeader = sign1.getProtectedHeader();
				CBORItem payloadItem = sign1.getPayload();
				byte[] payloadBytes;
				if (payloadItem instanceof CBORByteArray) {
					payloadBytes = ((CBORByteArray) payloadItem).getValue();
				} else {
					payloadBytes = payloadItem.encode();
				}
				CBORByteArray payload = new CBORByteArray(payloadBytes);
				SigStructure sigStructure = new SigStructureBuilder().signature1()
						.bodyAttributes(protectedHeader)
						.payload(payload)
						.build();
				
				LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
						"Signature structure reconstructed. Payload length: {} bytes, Algorithm: {}", 
						payloadBytes.length, protectedHeader.getAlg());
				
				// Log the signature structure details for debugging
				byte[] sigStructureBytes = sigStructure.encode();
				LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
						"Signature structure details - Header: {}, Payload hash: {}", 
						Hex.encodeHexString(sigStructureBytes).substring(0, Math.min(32, sigStructureBytes.length * 2)),
						Hex.encodeHexString(payloadBytes).substring(0, Math.min(32, payloadBytes.length * 2)));
				
				sig.initVerify(publicKey);
				sig.update(sigStructure.encode());
				byte[] signatureBytes = sign1.getSignature().getValue();
				
				LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
						"Signature verification parameters - Signature length: {} bytes, Structure length: {} bytes", 
						signatureBytes.length, sigStructure.encode().length);
				
				valid = sig.verify(signatureBytes);
				
				LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
						"Alternative verification result: {}", valid);
			} catch (Exception altException) {
				LOGGER.error(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
						"Both verification approaches failed with provider {}. Original: {}, Alternative: {}", 
						providerName, e.getMessage(), altException.getMessage(), altException);
				valid = false;
			}
		}
		
		LOGGER.debug(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Signature verification result: {}", valid);
		
		// TEMPORARY: Add detailed logging for debugging
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"=== VERIFICATION DEBUG ===");
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Raw verification result: {}", valid);
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Provider: {}", providerName);
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Public key algorithm: {}", publicKey.getAlgorithm());
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"=== END VERIFICATION DEBUG ===");
		
		CWTClaimsSet claimsSet = CWTClaimsSet.build(sign1.getPayload());
		Date date = claimsSet.getExp();
		long exp = date.getTime() / 1000;
		long currentTime = Instant.now().getEpochSecond();
		
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Token expiry check. Expiry: {}, Current: {}, Valid: {}", exp, currentTime, exp > currentTime);
		
		boolean finalResult = valid && (exp > currentTime);
		LOGGER.info(sessionId, "CBOR_VERIFY_INTERNAL", SignatureConstant.BLANK,
				"Final verification result: {} (signature: {}, expiry: {})", finalResult, valid, exp > currentTime);
		
		return finalResult;
	}
	
	/**
	 * Helper method to get hex representation of bytes around a specific offset
	 * for debugging CBOR errors
	 */
	private String getHexBytesAroundOffset(byte[] data, int offset) {
		int start = Math.max(0, offset - 10);
		int end = Math.min(data.length, offset + 10);
		StringBuilder sb = new StringBuilder();
		for (int i = start; i < end; i++) {
			if (i == offset) {
				sb.append(">>>");
			}
			sb.append(String.format("%02x ", data[i]));
			if (i == offset) {
				sb.append("<<< ");
			}
		}
		return sb.toString();
	}

	public static class EcdsaSECP256K1UsingSha256 extends EcdsaUsingShaAlgorithm
	{
		public EcdsaSECP256K1UsingSha256() {
			super(AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256,
					"SHA256withECDSA",
					EllipticCurves.SECP_256K1,
					64);
		}

		@Override
		public boolean isAvailable(){
			return true;
		}
	}

	public static class EcdsaBrainpoolP256r1UsingSha256 extends EcdsaUsingShaAlgorithm {
		public EcdsaBrainpoolP256r1UsingSha256() {
			super("ES256-BRAINPOOL",
					"SHA256withECDSA",
					EllipticCurves.SECP_256K1,  // Using SECP_256K1 as placeholder since brainpool not available in jose4j
					64);
		}

		@Override
		public boolean isAvailable() {
			return true;
		}
	}

	private String validateCborTrust(CBORSignatureVerifyRequestDto cborVerifyRequestDto, Certificate headerCertificate, String reqCertData) {
		boolean validateTrust = SignatureUtil.isIncludeAttrsValid(cborVerifyRequestDto.getValidateTrust());
		if (!validateTrust) {
			return SignatureConstant.TRUST_NOT_VERIFIED;
		}

		String domain = cborVerifyRequestDto.getDomain();
		if(!SignatureUtil.isDataValid(domain))
			return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;

		String certData = null;
		if (Objects.nonNull(headerCertificate)) {
			certData = keymanagerUtil.getPEMFormatedData(headerCertificate);
		}
		String trustCertData = certData == null ? reqCertData : certData;

		if (trustCertData == null)
			return SignatureConstant.TRUST_NOT_VERIFIED;

		CertificateTrustRequestDto trustRequestDto = new CertificateTrustRequestDto();
		trustRequestDto.setCertificateData(trustCertData);
		trustRequestDto.setPartnerDomain(domain);
		CertificateTrustResponeDto responseDto = partnerCertManagerService.verifyCertificateTrust(trustRequestDto);

		if (responseDto.getStatus()){
			return SignatureConstant.TRUST_VALID;
		}
		LOGGER.info(SignatureConstant.SESSIONID, "CBOR_VERIFY", SignatureConstant.BLANK,
				"CBOR Signature Verification Request - Trust Validation - Completed.");
		return SignatureConstant.TRUST_NOT_VALID;
	}

	// Add this utility method (use BouncyCastle)
	public static byte[] derToRaw(byte[] der, int keySizeBytes) throws IOException {
		ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
		BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
		BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
		byte[] rBytes = toFixedLength(r, keySizeBytes);
		byte[] sBytes = toFixedLength(s, keySizeBytes);
		byte[] raw = new byte[keySizeBytes * 2];
		System.arraycopy(rBytes, 0, raw, 0, keySizeBytes);
		System.arraycopy(sBytes, 0, raw, keySizeBytes, keySizeBytes);
		return raw;
	}

	private static byte[] toFixedLength(BigInteger b, int length) {
		byte[] bytes = b.toByteArray();
		if (bytes.length == length) return bytes;
		byte[] result = new byte[length];
		System.arraycopy(bytes, Math.max(0, bytes.length - length), result, Math.max(0, length - bytes.length), Math.min(length, bytes.length));
		return result;
	}

	public byte[] signRawMessage(String message, String applicationId, String referenceId) {
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		String providerName = certificateResponse.getProviderName();

		try {
			byte[] signature = SignatureUtil.signMessage(message, privateKey, providerName);
			return signature;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
			LOGGER.error(SignatureConstant.SESSIONID, "RAW_SIGN", SignatureConstant.BLANK, "Error signing message", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
					SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	public static byte[] signMessage(String message, PrivateKey privateKey, String providerName)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		Signature signature = (providerName != null && !providerName.isEmpty())
				? Signature.getInstance("SHA256withECDSA", providerName)
				: Signature.getInstance("SHA256withECDSA");
		signature.initSign(privateKey);
		signature.update(message.getBytes(StandardCharsets.UTF_8));
		return signature.sign();
	}

	public static boolean verifyMessage(byte[] data, byte[] signatureBytes, PublicKey publicKey, String providerName)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
		Signature signature = (providerName != null && !providerName.isEmpty())
				? Signature.getInstance("SHA256withECDSA", providerName)
				: Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(signatureBytes);
	}

	public boolean verifyRawMessage(String message, byte[] signatureBytes, String applicationId, String referenceId) {
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		PublicKey publicKey = certificateResponse.getCertificateEntry().getChain()[0].getPublicKey();
		String providerName = certificateResponse.getProviderName();
		try {
			return SignatureUtil.verifyMessage(message, signatureBytes, publicKey, providerName);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
			LOGGER.error(SignatureConstant.SESSIONID, "RAW_VERIFY", SignatureConstant.BLANK, "Error verifying message", e);
			throw new SignatureFailureException(SignatureErrorCode.VERIFY_ERROR.getErrorCode(),
					SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
		}
	}

	@ResponseBody
	@PostMapping("/signRawMessage")
	@ApiOperation(value = "Sign a raw message using ECDSA", notes = "Signs a message using the HSM-backed key for the given application and reference ID.")
	public ResponseWrapper<SignRawMessageResponseDto> signRawMessage(
			@RequestBody @Valid RequestWrapper<SignRawMessageRequestDto> requestDto) {
		byte[] signature = signRawMessage(
				requestDto.getRequest().getMessage(),
				requestDto.getRequest().getApplicationId(),
				requestDto.getRequest().getReferenceId()
		);
		String signatureBase64 = java.util.Base64.getEncoder().encodeToString(signature);
		SignRawMessageResponseDto responseDto = new SignRawMessageResponseDto();
		responseDto.setSignature(signatureBase64);
		responseDto.setTimestamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString());
		ResponseWrapper<SignRawMessageResponseDto> response = new ResponseWrapper<>();
		response.setResponse(responseDto);
		return response;
	}

	@ResponseBody
	@PostMapping("/verifyRawMessage")
	@ApiOperation(value = "Verify a raw message signature using ECDSA", notes = "Verifies a message signature using the HSM-backed key for the given application and reference ID.")
	public ResponseWrapper<VerifyRawMessageResponseDto> verifyRawMessage(
			@RequestBody @Valid RequestWrapper<VerifyRawMessageRequestDto> requestDto) {
		boolean valid = verifyRawMessage(
				requestDto.getRequest().getMessage(),
				java.util.Base64.getDecoder().decode(requestDto.getRequest().getSignature()),
				requestDto.getRequest().getApplicationId(),
				requestDto.getRequest().getReferenceId()
		);
		VerifyRawMessageResponseDto responseDto = new VerifyRawMessageResponseDto();
		responseDto.setValid(valid);
		responseDto.setMessage(valid ? "Signature valid" : "Signature invalid");
		responseDto.setTimestamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString());
		ResponseWrapper<VerifyRawMessageResponseDto> response = new ResponseWrapper<>();
		response.setResponse(responseDto);
		return response;
	}

	@Override
	public byte[] signBinary(byte[] data, String applicationId, String referenceId) {
		// Use your existing implementation or logic
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		String providerName = certificateResponse.getProviderName();
		try {
			return io.mosip.kernel.signature.util.SignatureUtil.signMessage(data, privateKey, providerName);
		} catch (Exception e) {
			LOGGER.error(SignatureConstant.SESSIONID, "BINARY_SIGN", SignatureConstant.BLANK, "Error signing binary data", e);
			throw new io.mosip.kernel.signature.exception.SignatureFailureException(
				io.mosip.kernel.signature.constant.SignatureErrorCode.SIGN_ERROR.getErrorCode(),
				io.mosip.kernel.signature.constant.SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	@Override
	public boolean verifyBinary(byte[] data, byte[] signatureBytes, String applicationId, String referenceId) {
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		PublicKey publicKey = certificateResponse.getCertificateEntry().getChain()[0].getPublicKey();
		String providerName = certificateResponse.getProviderName();
		try {
			return io.mosip.kernel.signature.util.SignatureUtil.verifyMessage(data, signatureBytes, publicKey, providerName);
		} catch (Exception e) {
			LOGGER.error(SignatureConstant.SESSIONID, "BINARY_VERIFY", SignatureConstant.BLANK, "Error verifying binary data", e);
			throw new io.mosip.kernel.signature.exception.SignatureFailureException(
				io.mosip.kernel.signature.constant.SignatureErrorCode.VERIFY_ERROR.getErrorCode(),
				io.mosip.kernel.signature.constant.SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
		}
	}

	@Override
	public SignatureResponseDto signCredential(SignCredentialRequestDto requestDto) {
		String message = requestDto.getMessage();
		String applicationId = requestDto.getApplicationId();
		String referenceId = requestDto.getReferenceId();
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		String providerName = certificateResponse.getProviderName(); // <-- fetch provider
		try {
			byte[] signature = SignatureUtil.signMessage(message, privateKey, providerName); // <-- use provider
			String signatureBase64 = Base64.encodeBase64String(signature);
			return new SignatureResponseDto(signatureBase64);
		} catch (Exception e) {
			LOGGER.error("signCredential", "SIGN_CREDENTIAL", "", "Error signing credential message", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(), SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	/**
	 * Signs a message using SHA256withECDSA and the provided private key.
	 * @param message the message to sign
	 * @param privateKey the private key
	 * @return the DER-encoded signature
	 */
	public static byte[] signMessage(String message, java.security.PrivateKey privateKey)
			throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.SignatureException {
		java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
		signature.initSign(privateKey);
		signature.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		return signature.sign();
	}

	@Override
	public boolean verifyCredential(io.mosip.kernel.signature.dto.VerifyCredentialRequestDto requestDto) {
		String message = requestDto.getMessage();
		String signatureBase64 = requestDto.getSignature();
		String applicationId = requestDto.getApplicationId();
		String referenceId = requestDto.getReferenceId();
		String timestamp = io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString();
		io.mosip.kernel.keymanagerservice.dto.SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, java.util.Optional.of(referenceId), timestamp);
		java.security.PublicKey publicKey = certificateResponse.getCertificateEntry().getChain()[0].getPublicKey();
		String providerName = certificateResponse.getProviderName();
		try {
			byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(signatureBase64);
			return io.mosip.kernel.signature.util.SignatureUtil.verifyMessage(message, signatureBytes, publicKey, providerName);
		} catch (Exception e) {
			LOGGER.error("verifyCredential", "VERIFY_CREDENTIAL", "", "Error verifying credential signature", e);
			throw new io.mosip.kernel.signature.exception.SignatureFailureException(io.mosip.kernel.signature.constant.SignatureErrorCode.VERIFY_ERROR.getErrorCode(), io.mosip.kernel.signature.constant.SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
		}
	}

}
