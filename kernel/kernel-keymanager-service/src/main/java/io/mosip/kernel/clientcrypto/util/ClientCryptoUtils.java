package io.mosip.kernel.clientcrypto.util;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;

public class ClientCryptoUtils {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(ClientCryptoUtils.class);

    public static byte[] decodeBase64Data(String anyBase64EncodedData){

        try{
            return CryptoUtil.decodeBase64(anyBase64EncodedData);
        } catch(IllegalArgumentException argException) {
            LOGGER.debug(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, "",
                    "Error Decoding Base64 URL Safe data, trying with Base64 normal decode.");
        }
        return CryptoUtil.decodeBase64(anyBase64EncodedData);
    }
}
