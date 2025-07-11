package io.mosip.kernel.signatureeeee.service;

import io.mosip.kernel.signatureeeee.dto.*;

public interface SignatureServicev2 extends SignatureService {
	/**
	 * JSON Web Signature(JWS) for the input data using input algorithm
	 *
	 * @param signatureReq
	 * @return the {@link SignResponseDto}
	 */
	public SignResponseDto signv2(SignRequestDtoV2 signatureReq);

}
