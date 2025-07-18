package io.mosip.kernel.signature.util;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.List;
import java.security.SecureRandom;
import java.security.PublicKey;
import java.security.NoSuchProviderException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.constant.SignatureConstant;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.exception.SignatureFailureException;
/**
 * Utility class for Signature Service
 * 
 * @author Mahammed Taheer
  * @since 1.1.5.3
 *
 */

public class SignatureUtil {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureUtil.class);


    public static boolean isDataValid(String anyData) {
        return anyData != null && !anyData.trim().isEmpty();
    }


    public static boolean isJsonValid(String jsonInString) {
        try {
           ObjectMapper mapper = new ObjectMapper();
           mapper.readTree(jsonInString);
           return true;
        } catch (IOException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                        "Provided JSON Data to sign value is invalid.");
        }
        return false;
    }

    public static boolean isIncludeAttrsValid(Boolean includes) {
        if (Objects.isNull(includes)) {
            return SignatureConstant.DEFAULT_INCLUDES;
        }
        return includes;
    }

	public static boolean isCertificateDatesValid(X509Certificate x509Cert) {

		try {
			Date currentDate = Date.from(DateUtils.getUTCCurrentDateTime().atZone(ZoneId.systemDefault()).toInstant());
			x509Cert.checkValidity(currentDate);
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException exp) {
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate dates are not valid.");
		}
		try {
			// Checking both system default timezone & UTC Offset timezone. Issue found in
			// reg-client during trust validation.
			x509Cert.checkValidity();
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException exp) {
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate dates are not valid.");
		}
		return false;
	}
	public static JWSHeader getJWSHeader(String signAlgorithm, boolean b64JWSHeaderParam, boolean includeCertificate,
			boolean includeCertHash, String certificateUrl, X509Certificate x509Certificate, String uniqueIdentifier, 
			boolean includeKeyId) {

		JWSAlgorithm jwsAlgorithm;
		switch (signAlgorithm) {
			case "RS256":
				jwsAlgorithm = JWSAlgorithm.RS256;
				break;
			case "PS256":
				jwsAlgorithm = JWSAlgorithm.PS256;
				break;
			default:
				jwsAlgorithm = JWSAlgorithm.PS256;
				break;
		}

		JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(jwsAlgorithm);

		if (!b64JWSHeaderParam)
			jwsHeaderBuilder = jwsHeaderBuilder.base64URLEncodePayload(false)
								.criticalParams(Collections.singleton(SignatureConstant.B64));

		if (includeCertificate) {
			try {
				Base64 signCert = Base64.encode(x509Certificate.getEncoded());
				List<Base64> x5c = new ArrayList<>();
				x5c.add(signCert);
				jwsHeaderBuilder = jwsHeaderBuilder.x509CertChain(x5c);
			} catch (CertificateEncodingException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate not able to parse while adding to jws header.");
			}
		}

		if (includeCertHash) {
			try {
				jwsHeaderBuilder = jwsHeaderBuilder.x509CertSHA256Thumbprint(Base64URL.encode(DigestUtils.sha256(x509Certificate.getEncoded())));
			} catch (CertificateEncodingException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate not able to parse while adding to jws header.");
			}
		}

		if (Objects.nonNull(certificateUrl)) {
			try {
				jwsHeaderBuilder.x509CertURL(new URI(certificateUrl));
			} catch (URISyntaxException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate URI not able to parse while adding to jws header.");
			}
		}
		String keyId = convertHexToBase64(uniqueIdentifier);
		if (includeKeyId && Objects.nonNull(keyId)) {
			jwsHeaderBuilder.keyID(keyId);
		}

		return jwsHeaderBuilder.build();
	}

	public static byte[] buildSignData(JWSHeader jwsHeader, byte[] actualDataToSign) {

		byte[] jwsHeaderBytes = jwsHeader.toBase64URL().toString().getBytes(StandardCharsets.UTF_8);
		byte[] jwsSignData = new byte[jwsHeaderBytes.length + actualDataToSign.length + 1];
		System.arraycopy(jwsHeaderBytes, 0, jwsSignData, 0, jwsHeaderBytes.length);
		jwsSignData[jwsHeaderBytes.length] = (byte) '.';
		System.arraycopy(actualDataToSign, 0, jwsSignData, jwsHeaderBytes.length + 1, actualDataToSign.length);
		return jwsSignData;
	}
	public static String convertHexToBase64(String anyHexString) {
		try {
			
			return CryptoUtil.encodeBase64(HMACUtils2.generateHash(Hex.decodeHex(anyHexString)));
		} catch (DecoderException | NoSuchAlgorithmException e) {
			// ignore this exception.
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
			"Warning thrown when converting hex data to base64 encoded data.");
			// not throwing exception, as this function is added to include kid in jwt signature.
			// in case any error in conversion kid will not be added in jwt header.
		}
		return null;
	}

    /**
     * Signs a message using the provided ECDSA private key and SHA-256, with provider.
     *
     * @param message      The message to sign (as a String, UTF-8).
     * @param privateKey   The ECDSA private key (HSM-backed or otherwise).
     * @param providerName The JCA provider name (e.g., "SunPKCS11-Luna"), or null for default.
     * @return The signature as a byte array (DER-encoded).
     */
    public static byte[] signMessage(String message, PrivateKey privateKey, String providerName)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature signature = (providerName != null && !providerName.isEmpty())
                ? Signature.getInstance("SHA256withECDSA", providerName)
                : Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    /**
     * Signs binary data using the provided ECDSA private key and SHA-256.
     * Returns the raw (r||s) signature as a byte array (for COSE/JWS).
     *
     * @param data         The data to sign.
     * @param privateKey   The ECDSA private key (HSM-backed or otherwise).
     * @param providerName The JCA provider name (e.g., "SunPKCS11-Luna"), or null for default.
     * @return The raw (r||s) signature as a byte array.
     */
    public static byte[] signMessage(byte[] data, PrivateKey privateKey, String providerName) {
        try {
            Signature signature;
            if (Objects.nonNull(providerName) && !providerName.isEmpty()) {
                signature = Signature.getInstance(SignatureConstant.EC256_ALGORITHM, providerName);
            } else {
                signature = Signature.getInstance(SignatureConstant.EC256_ALGORITHM);
            }
            signature.initSign(privateKey, new SecureRandom());
            signature.update(data);
            byte[] derSignature = signature.sign();
            // Convert DER to raw (r||s) for COSE/JWS
            return EcdsaUsingShaAlgorithm.convertDerToConcatenated(derSignature, SignatureConstant.EC256_SIGNATURE_LENGTH);
        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
                    "Error while signing the data.", e);
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                    SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }

    /**
     * Verifies a message using the provided ECDSA public key and SHA-256.
     *
     * @param message        The original message (as a String, UTF-8).
     * @param signatureBytes The signature to verify (DER-encoded).
     * @param publicKey      The ECDSA public key.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifyMessage(String message, byte[] signatureBytes, java.security.PublicKey publicKey)
            throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }

    /**
     * Verifies a message using the provided ECDSA public key and SHA-256, with provider.
     *
     * @param message        The original message (as a String, UTF-8).
     * @param signatureBytes The signature to verify (DER-encoded).
     * @param publicKey      The ECDSA public key.
     * @param providerName   The JCA provider name (e.g., "SunPKCS11-Luna"), or null for default.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifyMessage(String message, byte[] signatureBytes, PublicKey publicKey, String providerName)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature signature = (providerName != null && !providerName.isEmpty())
                ? Signature.getInstance("SHA256withECDSA", providerName)
                : Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
    }

    /**
     * Verifies binary data using the provided ECDSA public key and SHA-256, with provider.
     *
     * @param data           The original data (as a byte array).
     * @param signatureBytes The signature to verify (DER-encoded).
     * @param publicKey      The ECDSA public key.
     * @param providerName   The JCA provider name (e.g., "SunPKCS11-Luna"), or null for default.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifyMessage(byte[] data, byte[] signatureBytes, java.security.PublicKey publicKey, String providerName)
            throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.SignatureException, java.security.NoSuchProviderException {
        Signature signature = (providerName != null && !providerName.isEmpty())
                ? Signature.getInstance("SHA256withECDSA", providerName)
                : Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }


}
