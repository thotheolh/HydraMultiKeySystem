package HydraApplet ;

import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * Utility methods to work with the SECP256k1 curve. This class is not meant to
 * be instantiated, but its init method must be called during applet
 * installation.
 */
public class ECC {
	protected static byte[] EC_P256R1_FIELD_A = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFC };
	protected static byte[] EC_P256R1_FIELD_B = { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
			(byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76,
			(byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC,
			(byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27,
			(byte) 0xD2, (byte) 0x60, (byte) 0x4B };
	protected static byte[] EC_P256R1_FIELD_G = { (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
			(byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5,
			(byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81,
			(byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45,
			(byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2,
			(byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
			(byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57,
			(byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68,
			(byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5 };
	protected static byte[] EC_P256R1_FIELD_R = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7,
			(byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC,
			(byte) 0x63, (byte) 0x25, (byte) 0x51 };
	protected static byte[] EC_P256R1_FP = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };	

	static final byte K = (byte) 0x01;

	static final short KEY_SIZE = 256;

	public static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

	private KeyAgreement ecPointMultiplier;
	ECPrivateKey tmpECPrivateKey;

	/**
	 * Allocates objects needed by this class. Must be invoked during the applet
	 * installation exactly 1 time.
	 */
	ECC() {
		this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
		this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_SIZE,
				false);
		setCurveParameters(tmpECPrivateKey);
	}

	/**
	 * Sets the SECP256k1 curve parameters to the given ECKey (public or private).
	 *
	 * @param key the key where the curve parameters must be set
	 */
	void setCurveParameters(ECKey key) {
		key.setA(EC_P256R1_FIELD_A, (short) 0x00, (short) EC_P256R1_FIELD_A.length);
		key.setB(EC_P256R1_FIELD_B, (short) 0x00, (short) EC_P256R1_FIELD_B.length);
		key.setFieldFP(EC_P256R1_FP, (short) 0x00, (short) EC_P256R1_FP.length);
		key.setG(EC_P256R1_FIELD_G, (short) 0x00, (short) EC_P256R1_FIELD_G.length);
		key.setR(EC_P256R1_FIELD_R, (short) 0x00, (short) EC_P256R1_FIELD_R.length);
		key.setK(K);
	}

	public static boolean checkCurveParameters(ECKey eckey, byte[] tmpbuffer, short tmpoffset) {

		eckey.getA(tmpbuffer, tmpoffset);
		if (0 != Util.arrayCompare(tmpbuffer, tmpoffset, EC_P256R1_FIELD_A, (short) 0, (short) EC_P256R1_FIELD_A.length))
			return false;
		eckey.getB(tmpbuffer, tmpoffset);
		if (0 != Util.arrayCompare(tmpbuffer, tmpoffset, EC_P256R1_FIELD_B, (short) 0, (short) EC_P256R1_FIELD_B.length))
			return false;
		eckey.getG(tmpbuffer, tmpoffset);
		if (0 != Util.arrayCompare(tmpbuffer, tmpoffset, EC_P256R1_FIELD_G, (short) 0, (short) EC_P256R1_FIELD_G.length))
			return false;
		eckey.getR(tmpbuffer, tmpoffset);
		if (0 != Util.arrayCompare(tmpbuffer, tmpoffset, EC_P256R1_FIELD_R, (short) 0, (short) EC_P256R1_FIELD_R.length))
			return false;
		eckey.getField(tmpbuffer, tmpoffset);
		if (0 != Util.arrayCompare(tmpbuffer, tmpoffset, EC_P256R1_FP, (short) 0, (short) EC_P256R1_FP.length))
			return false;
		if (eckey.getK() != K)
			return false;

		return true;
	}

	/**
	 * Derives the public key from the given private key and outputs it in the
	 * pubOut buffer. This is done by multiplying the private key by the G point of
	 * the curve.
	 *
	 * @param privateKey the private key
	 * @param pubOut     the output buffer for the public key
	 * @param pubOff     the offset in pubOut
	 * @return the length of the public key
	 */
	short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
		return multiplyPoint(privateKey, EC_P256R1_FIELD_G, (short) 0, (short) EC_P256R1_FIELD_G.length, pubOut, pubOff);
	}

	/**
	 * Derives the public key from the given private key and outputs it in the
	 * pubOut buffer. This is done by multiplying the private key by the G point of
	 * the curve.
	 *
	 * @param privateKey the private key
	 * @param pubOut     the output buffer for the public key
	 * @param pubOff     the offset in pubOut
	 * @return the length of the public key
	 */
	short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
		tmpECPrivateKey.setS(privateKey, privOff, (short) (KEY_SIZE / 8));
		return derivePublicKey(tmpECPrivateKey, pubOut, pubOff);
	}

	/**
	 * Multiplies a scalar in the form of a private key by the given point.
	 * Internally uses a special version of EC-DH supported since JavaCard 3.0.5
	 * which outputs both X and Y in their uncompressed form.
	 *
	 * @param privateKey the scalar in a private key object
	 * @param point      the point to multiply
	 * @param pointOff   the offset of the point
	 * @param pointLen   the length of the point
	 * @param out        the output buffer
	 * @param outOff     the offset in the output buffer
	 * @return the length of the data written in the out buffer
	 */
	short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out,
			short outOff) {
		ecPointMultiplier.init(privateKey);
		return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
	}
}
