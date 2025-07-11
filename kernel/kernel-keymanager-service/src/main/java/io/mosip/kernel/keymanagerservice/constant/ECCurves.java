package io.mosip.kernel.keymanagerservice.constant;

/**
 * Enum for Elliptic Curve names
 * 
 * @author Srinivasan
 * @since 1.2.0
 */
public enum ECCurves {
	SECP256K1("secp256k1"),
	SECP256R1("secp256r1"),
	ED25519("ed25519"),
	BRAINPOOLP256R1("brainpoolP256r1");

	private final String curveName;

	ECCurves(String curveName) {
		this.curveName = curveName;
	}

	public String getCurveName() {
		return curveName;
	}
}
