package io.mosip.kernel.signature.util;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import COSE.HeaderKeys;
import COSE.Attribute;

public class COSESign1Util {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static String sign(byte[] payload, ECPrivateKey privateKey) throws CoseException {
        OneKey oneKey = new OneKey(null, privateKey);
        Sign1Message msg = new Sign1Message();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        msg.SetContent(payload);
        msg.sign(oneKey);
        return Base64.getEncoder().encodeToString(msg.EncodeToBytes());
    }

    public static boolean verify(byte[] coseSign1, ECPublicKey publicKey, byte[] expectedPayload) throws CoseException {
        Sign1Message msg = (Sign1Message) Sign1Message.DecodeFromBytes(coseSign1);
        OneKey oneKey = new OneKey(publicKey, null);
        boolean valid = msg.validate(oneKey);
        if (!valid) return false;
        byte[] payload = msg.GetContent();
        return java.util.Arrays.equals(payload, expectedPayload);
    }

    public static byte[] jsonToBytes(String jsonBase64) throws Exception {
        String json = new String(Base64.getDecoder().decode(jsonBase64));
        return objectMapper.writeValueAsBytes(objectMapper.readTree(json));
    }
} 