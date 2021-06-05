package hydra.utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

	private static SecureRandom rand = new SecureRandom();

	public static byte[] getSecureRandomBytes(int len) {
		byte[] b = new byte[len];
		rand.nextBytes(b);
		return b;
	}

	public static KeyPair generateECKeyPair(String algo)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(algo));
		java.security.spec.ECParameterSpec ecParameterSpec = parameters
				.getParameterSpec(java.security.spec.ECParameterSpec.class);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(ecParameterSpec);
		KeyPair kp = keyGen.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
		return kp;
	}

	public static byte[] getPrivateKeyBytes(KeyPair kp, int keyLength) {
		ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
		byte[] s = privKey.getS().toByteArray();
		byte[] outFormattedPrivKey = new byte[keyLength];
		if (s.length > keyLength) {
			System.arraycopy(s, 1, outFormattedPrivKey, 0, keyLength);
		} else if (s.length < keyLength) {
			System.arraycopy(s, 0, outFormattedPrivKey, keyLength - s.length, s.length);
		} else {
			System.arraycopy(s, 0, outFormattedPrivKey, 0, keyLength);
		}
		return outFormattedPrivKey;
	}

	public static byte[] getPrivateKeyBytes(PrivateKey privKey, int keyLength) {
		byte[] s = ((ECPrivateKey) privKey).getS().toByteArray();
		byte[] outFormattedPrivKey = new byte[keyLength];
		if (s.length > keyLength) {
			System.arraycopy(s, 1, outFormattedPrivKey, 0, keyLength);
		} else if (s.length < keyLength) {
			System.arraycopy(s, 0, outFormattedPrivKey, keyLength - s.length, s.length);
		} else {
			System.arraycopy(s, 0, outFormattedPrivKey, 0, keyLength);
		}
		return outFormattedPrivKey;
	}

	public static byte[] getPublicKeyBytes(KeyPair kp, int keyLength, boolean hasHeader) {
		int bytesToCopy = 0;
		byte[] outFormattedPubKey = null;
		int cursor = 0;
		int copy = 0;

		if (!hasHeader) {
			bytesToCopy = 2 * keyLength;
			outFormattedPubKey = new byte[bytesToCopy];
		} else {
			bytesToCopy = 1 + (2 * keyLength);
			outFormattedPubKey = new byte[bytesToCopy];
			outFormattedPubKey[0] = (byte) 0x04;
			cursor++;
		}

		// Handle key material via key length checking
		byte[] X = ((ECPublicKey) kp.getPublic()).getW().getAffineX().toByteArray();
		if (X.length > keyLength) {
			copy = 1;
			System.arraycopy(X, copy, outFormattedPubKey, cursor, keyLength);
		} else if (X.length < keyLength) {
			copy = keyLength - X.length;
			System.arraycopy(X, 0, outFormattedPubKey, cursor + copy, X.length);
		} else {
			System.arraycopy(X, copy, outFormattedPubKey, cursor, keyLength);
		}
		cursor += keyLength;
		copy = 0;

		byte[] Y = ((ECPublicKey) kp.getPublic()).getW().getAffineY().toByteArray();
		if (Y.length > keyLength) {
			copy = 1;
			System.arraycopy(Y, copy, outFormattedPubKey, cursor, keyLength);
		} else if (Y.length < keyLength) {
			copy = keyLength - Y.length;
			System.arraycopy(Y, 0, outFormattedPubKey, cursor + copy, Y.length);
		} else {
			System.arraycopy(Y, copy, outFormattedPubKey, cursor, keyLength);
		}

		return outFormattedPubKey;
	}

	public static PublicKey getPublicKey(byte[] xBytes, byte[] yBytes)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
		BigInteger x = new BigInteger(BinUtils.toHexString(xBytes), 16);
		BigInteger y = new BigInteger(BinUtils.toHexString(yBytes), 16);
		ECPoint w = new ECPoint(x, y);
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		java.security.spec.ECParameterSpec ecParameterSpec = parameters
				.getParameterSpec(java.security.spec.ECParameterSpec.class);
		ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
	}

	public static PublicKey getPublicKey(boolean hasASNHeader, byte[] xyBytes, String ecAlgo)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
		int keyLength = xyBytes.length / 2;
		byte[] xBytes = new byte[keyLength];
		byte[] yBytes = new byte[keyLength];
		if (hasASNHeader && xyBytes[0] == (byte) 0x04) {
			System.arraycopy(xyBytes, 1, xBytes, 0, keyLength);
			System.arraycopy(xyBytes, keyLength + 1, yBytes, 0, keyLength);
		} else {
			System.arraycopy(xyBytes, 0, xBytes, 0, keyLength);
			System.arraycopy(xyBytes, keyLength, yBytes, 0, keyLength);
		}
		BigInteger x = new BigInteger(BinUtils.toHexString(xBytes), 16);
		BigInteger y = new BigInteger(BinUtils.toHexString(yBytes), 16);
		ECPoint w = new ECPoint(x, y);
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(ecAlgo));
		java.security.spec.ECParameterSpec ecParameterSpec = parameters
				.getParameterSpec(java.security.spec.ECParameterSpec.class);
		ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
	}

	public static PrivateKey getPrivateKey(byte[] sBytes, String ecAlgo)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
		BigInteger s = new BigInteger(BinUtils.toHexString(sBytes), 16);
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec(ecAlgo));
		java.security.spec.ECParameterSpec ecParameterSpec = parameters
				.getParameterSpec(java.security.spec.ECParameterSpec.class);
		ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return (ECPrivateKey) keyFactory.generatePrivate(ecPrivateKeySpec);
	}

	public static KeyPair getKeyPair(boolean hasASNHeader, byte[] publicXYBytes, byte[] privateBytes, String ecAlgo)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
		return new KeyPair(getPublicKey(hasASNHeader, publicXYBytes, ecAlgo), getPrivateKey(privateBytes, ecAlgo));
	}

	public static byte[] jceECPublicKey256ToBytes(ECPublicKey pubKey) {
		byte[] tmpECPublicKey = new byte[65];
		int cursor = 0;
		int copy = 0;
		boolean isProblematicKey = false;
		tmpECPublicKey[cursor] = (byte) 0x04;
		cursor++;
		// Handle key material via key length checking
		byte[] X = pubKey.getW().getAffineX().toByteArray();
		if (X.length > 32) {
			copy = 1;
			System.arraycopy(X, copy, tmpECPublicKey, cursor, 32);
		} else if (X.length < 32) {
			copy = 32 - X.length;
			System.arraycopy(X, 0, tmpECPublicKey, cursor + copy, X.length);
		} else {
			System.arraycopy(X, copy, tmpECPublicKey, cursor, 32);
		}
		cursor += 32;
		copy = 0;

		byte[] Y = pubKey.getW().getAffineY().toByteArray();
		if (Y.length > 32) {
			copy = 1;
			System.arraycopy(Y, copy, tmpECPublicKey, cursor, 32);
		} else if (Y.length < 32) {
			copy = 32 - Y.length;
			System.arraycopy(Y, 0, tmpECPublicKey, cursor + copy, Y.length);
		} else {
			System.arraycopy(Y, copy, tmpECPublicKey, cursor, 32);
		}
		cursor = 0;
		copy = 0;

		System.out.println("rX: " + BinUtils.toHexString(X));
		System.out.println("rY: " + BinUtils.toHexString(Y));

		if (!isProblematicKey) {
			return tmpECPublicKey;
		} else {
			return null;
		}
	}

	public static byte[] deriveECSharedSecret(boolean hasASNHeader, byte[] pubKey, KeyPair kp)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException,
			InvalidKeyException {
		byte[] xBytes = new byte[32];
		byte[] yBytes = new byte[32];
		if (hasASNHeader && pubKey[0] == (byte) 0x04) {
			System.arraycopy(pubKey, 1, xBytes, 0, 32);
			System.arraycopy(pubKey, 33, yBytes, 0, 32);
		} else {
			System.arraycopy(pubKey, 0, xBytes, 0, 32);
			System.arraycopy(pubKey, 32, yBytes, 0, 32);
		}
		ECPublicKey targetPubKey = (ECPublicKey) getPublicKey(xBytes, yBytes);
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(kp.getPrivate());
		ka.doPhase(targetPubKey, true);
		return ka.generateSecret();
	}
	
	public static byte[] deriveECSharedSecret(boolean hasASNHeader, byte[] pubKey, PrivateKey ecPrivateKey)
			throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException,
			InvalidKeyException {
		byte[] xBytes = new byte[32];
		byte[] yBytes = new byte[32];
		if (hasASNHeader && pubKey[0] == (byte) 0x04) {
			System.arraycopy(pubKey, 1, xBytes, 0, 32);
			System.arraycopy(pubKey, 33, yBytes, 0, 32);
		} else {
			System.arraycopy(pubKey, 0, xBytes, 0, 32);
			System.arraycopy(pubKey, 32, yBytes, 0, 32);
		}
		ECPublicKey targetPubKey = (ECPublicKey) getPublicKey(xBytes, yBytes);
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(ecPrivateKey);
		ka.doPhase(targetPubKey, true);
		return ka.generateSecret();
	}

	public static byte[] aesECBWrapKey(byte[] kek, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		SecretKeySpec kekKey = new SecretKeySpec(kek, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, kekKey);
		return cipher.doFinal(data);
	}

	public static byte[] aesECBUnwrapKey(byte[] kek, byte[] data)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		SecretKeySpec kekKey = new SecretKeySpec(kek, "AES");
		cipher.init(Cipher.DECRYPT_MODE, kekKey);
		return cipher.doFinal(data);
	}

	public static Cipher getContentCryptoCipher(boolean isEncrypt, byte[] key, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		if (isEncrypt) {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		}
		return cipher;
	}

	public static Mac getContentMac(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac cipher = Mac.getInstance("HmacSHA256");
		SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
		cipher.init(secretKey);
		return cipher;
	}

	public static byte[][] processContentEncrypt(boolean isFinal, Cipher cipher, Mac hmac, byte[] data, int off,
			int len, byte[] metadata, int metaOff, int metaLen) throws IllegalBlockSizeException, BadPaddingException {
		byte[] cipherText = null;
		if (isFinal) {
//			System.out.println("CryptoUtils :: processContentEncrypt :: Final ...");
			if (data != null || len != 0) {
				cipherText = cipher.doFinal(data, off, len);
			} else {
				cipherText = cipher.doFinal();
			}
			if (metadata != null || metaLen != 0) {
//				System.out.println("CryptoUtils :: processContentEncrypt :: MACing Meta: " + BinUtils.toHexString(metadata, metaOff, metaLen));
				hmac.update(metadata, metaOff, metaLen);
			}
			if (cipherText != null) {
//				System.out.println("CryptoUtils :: processContentEncrypt :: MAC Update: " + BinUtils.toHexString(cipherText));
				hmac.update(cipherText);
			}
			byte[] hmacData = hmac.doFinal();
			return new byte[][] { cipherText, hmacData };
		} else {
//			System.out.println("CryptoUtils :: processContentEncrypt :: Update ...");
			if (data != null || len != 0) {
				cipherText = cipher.update(data, off, len);
			}
			if (metadata != null || metaLen != 0) {
//				System.out.println("CryptoUtils :: processContentEncrypt :: MACing Meta: " + BinUtils.toHexString(metadata, metaOff, metaLen));
				hmac.update(metadata, metaOff, metaLen);
			}
			if (cipherText != null) {
//				System.out.println("CryptoUtils :: processContentEncrypt :: MAC Update: " + BinUtils.toHexString(cipherText));
				hmac.update(cipherText);
			}
			return new byte[][] { cipherText };
		}
	}

}
