package io.mosip.kernel.signatureeeee.service.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signatureeeee.constant.SignatureConstant;
import io.mosip.kernel.signatureeeee.constant.SignatureErrorCode;
import io.mosip.kernel.signatureeeee.exception.SignatureFailureException;
import io.mosip.kernel.signatureeeee.service.SignatureProvider;

public class BrainpoolP256r1SignatureProviderImpl implements SignatureProvider {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(BrainpoolP256r1SignatureProviderImpl.class);
    private static final int BRAINPOOLP256R1_SIGNATURE_LENGTH = 64; // 32 bytes R + 32 bytes S

    static {
        // Ensure BouncyCastle provider is available
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public String sign(PrivateKey privateKey, byte[] signData, String providerName) {
        try {
            // Initialize signature with BrainpoolP256r1
            Signature signatureObj = Signature.getInstance("SHA256withECDSA", providerName);
            signatureObj.initSign(privateKey);
            signatureObj.update(signData);
            byte[] derSignature = signatureObj.sign();

            // Convert DER format to concatenated R||S
            byte[] concatenated = convertDerToConcatenated(derSignature, BRAINPOOLP256R1_SIGNATURE_LENGTH);
            return CryptoUtil.encodeBase64(concatenated);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException |
                 IOException | NoSuchProviderException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
                    "Error while signing with BrainpoolP256r1", e);
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                    SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }

    /**
     * Converts DER-encoded ECDSA signature to concatenated R||S format
     */
    private byte[] convertDerToConcatenated(byte[] derSignature, int outputLength) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(derSignature);
        if (seq.size() != 2) {
            throw new IOException("Invalid DER sequence length");
        }

        // Extract R and S values
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();

        // Convert to fixed-length byte arrays
        byte[] rBytes = toUnsignedByteArray(r, outputLength/2);
        byte[] sBytes = toUnsignedByteArray(s, outputLength/2);

        // Concatenate R and S
        byte[] concatenated = new byte[outputLength];
        System.arraycopy(rBytes, 0, concatenated, 0, rBytes.length);
        System.arraycopy(sBytes, 0, concatenated, outputLength/2, sBytes.length);
        return concatenated;
    }

    /**
     * Converts BigInteger to fixed-length unsigned byte array
     */
    private byte[] toUnsignedByteArray(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();

        // Remove sign byte if present
        int start = (bytes.length > length && bytes[0] == 0) ? 1 : 0;
        int count = bytes.length - start;

        if (count > length) {
            throw new IllegalArgumentException("Value too large for target length");
        }

        byte[] result = new byte[length];
        System.arraycopy(bytes, start, result, length - count, count);
        return result;
    }
}