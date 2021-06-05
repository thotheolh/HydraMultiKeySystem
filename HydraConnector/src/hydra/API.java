package hydra;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import hydra.hw.sc.APDUResult;
import hydra.hw.sc.Device;
import hydra.hw.sc.DeviceManager;
import hydra.utils.BinUtils;
import hydra.utils.CryptoUtils;

public class API {

	private DeviceManager devMan = null;
	private ArrayList<Device> devList = null;

	public API() {
		try {
			devMan = DeviceManager.getInstance(true);
			devList = devMan.getDevices();
		} catch (CardException e) {
			e.printStackTrace();
		}
	}

	public ArrayList<Device> devices() {
		return devList;
	}

	public void refreshDevices(boolean displayLog) {
		try {
			devList = null;
			devMan.refreshDevices(displayLog);
			devList = devMan.getDevices();
		} catch (CardException e) {
			e.printStackTrace();
		}
	}

	public APDUResult rawGetPublicKey(Device hwDev) throws CardException {
		if (hwDev != null) {
			return new APDUResult(hwDev.send(new CommandAPDU((byte) 0xB0, (byte) 0xCA, (byte) 0x00, (byte) 0x00, 65)));
		} else {
			throw new CardException("Device not found");
		}
	}

	public APDUResult rawECDHCryptoOp(Device hwDev, boolean isDecrypt, byte[] targetPublicKey, byte[] targetPublicKey2,
			byte[] wrappedSecret) throws CardException {
		byte p1 = (byte) 0x01;
		byte p2 = (byte) 0x04;

		if (!isDecrypt) {
			p1 = (byte) 0x02;
		}

		byte[] data = null;
		if (isDecrypt) {
			data = new byte[67 + wrappedSecret.length];
		} else {
			data = new byte[67 + wrappedSecret.length + targetPublicKey2.length];
		}
		data[0] = (byte) 0x01;
		data[1] = (byte) 0x00;
//		System.out
//				.println("API :: rawECDHCryptoOp :: ECDH Target Public Key: " + BinUtils.toHexString(targetPublicKey));
		System.arraycopy(targetPublicKey, 0, data, 2, targetPublicKey.length);
//		System.out.println("API :: rawECDHCryptoOp :: Wrapped Secret: " + BinUtils.toHexString(wrappedSecret));
		System.arraycopy(wrappedSecret, 0, data, 67, wrappedSecret.length);

		if (!isDecrypt) {
//			System.out.println(
//					"API :: rawECDHCryptoOp :: ECDH Target Public Key 2: " + BinUtils.toHexString(targetPublicKey2));
			System.arraycopy(targetPublicKey2, 0, data, 67 + wrappedSecret.length, targetPublicKey2.length);
		}

//		System.out.println("API :: rawECDHCryptoOp :: ECDH Input Data: " + BinUtils.toHexString(data));
		if (hwDev != null) {
			return new APDUResult(hwDev.send(new CommandAPDU((byte) 0xB0, (byte) 0x2A, p1, p2, data, 255)));
		} else {
			throw new CardException("Device not found");
		}
	}
	
	public APDUResult[] doECDHDecrypt(Device hwDev1, Device hwDev2, byte[] targetPublicKey1, byte[] targetPublicKey2,
			byte[] wrappedSecret1, byte[] wrappedSecret2) throws CardException {
		APDUResult[] results = new APDUResult[2];
		results[0] = rawECDHCryptoOp(hwDev1, true, targetPublicKey1, null, wrappedSecret1);
		results[1] = rawECDHCryptoOp(hwDev2, true, targetPublicKey2, null, wrappedSecret2);
		return results;
	}

	public APDUResult[] doECDHReencrypt(Device hwDev1, Device hwDev2, byte[] wrappingPublicKey1,
			byte[] wrappingPublicKey2, byte[] targetPublicKey1, byte[] targetPublicKey2, byte[] wrappedSecret1,
			byte[] wrappedSecret2) throws CardException {
		APDUResult[] results = new APDUResult[2];
		results[0] = rawECDHCryptoOp(hwDev1, false, wrappingPublicKey1, targetPublicKey1, wrappedSecret1);
		results[1] = rawECDHCryptoOp(hwDev2, false, wrappingPublicKey2, targetPublicKey2, wrappedSecret2);
		return results;
	}

	public static void main(String[] args) {
		API api = new API();
		Device dev1 = null;
		Device dev2 = null;
		APDUResult res1 = null;
		APDUResult res2 = null;
		byte[] dev1Pub = null;
		byte[] dev2Pub = null;
		if (api.devices().size() >= 2) {
			dev1 = api.devices().get(0);
			dev2 = api.devices().get(1);
			try {
				res1 = api.rawGetPublicKey(dev1);
				res2 = api.rawGetPublicKey(dev2);
				if (res1.isSuccess() && res2.isSuccess()) {
					dev1Pub = res1.getResult();
					dev2Pub = res2.getResult();
					System.out.println("Device 1 Public Key: " + BinUtils.toHexString(dev1Pub)
							+ "\r\nDevice 2 Public Key: " + BinUtils.toHexString(dev2Pub));
					KeyPair kp1 = CryptoUtils.generateECKeyPair("secp256r1");
					KeyPair kp2 = CryptoUtils.generateECKeyPair("secp256r1");

					byte[] kp1PubKey = CryptoUtils.getPublicKeyBytes(kp1, 32, true);
					byte[] kp2PubKey = CryptoUtils.getPublicKeyBytes(kp2, 32, true);

					byte[] kp1PubKey1 = CryptoUtils.jceECPublicKey256ToBytes((ECPublicKey) kp1.getPublic());
					byte[] kp2PubKey1 = CryptoUtils.jceECPublicKey256ToBytes((ECPublicKey) kp2.getPublic());
					System.out.println("Client 1 Public Key: " + BinUtils.toHexString(kp1PubKey));
					System.out.println("Client 2 Public Key: " + BinUtils.toHexString(kp2PubKey));

					byte[] ssRaw1 = CryptoUtils.deriveECSharedSecret(true, dev1Pub, kp1);
					byte[] ssRaw2 = CryptoUtils.deriveECSharedSecret(true, dev2Pub, kp2);
					MessageDigest hash = MessageDigest.getInstance("SHA-256");
					byte[] kek1 = hash.digest(ssRaw1);
					hash.reset();
					byte[] kek2 = hash.digest(ssRaw2);

					byte[] random1 = CryptoUtils.getSecureRandomBytes(32);
					byte[] random2 = CryptoUtils.getSecureRandomBytes(32);

					byte[] wrapped1 = CryptoUtils.aesECBWrapKey(kek1, random1);
					byte[] wrapped2 = CryptoUtils.aesECBWrapKey(kek2, random2);

					System.out.println("Secret #1: " + BinUtils.toHexString(random1));
					System.out.println("Secret #2: " + BinUtils.toHexString(random2));
					System.out.println("Wrapped #1: " + BinUtils.toHexString(wrapped1));
					System.out.println("Wrapped #2: " + BinUtils.toHexString(wrapped2));

					APDUResult[] results = api.doECDHDecrypt(dev1, dev2, kp1PubKey, kp2PubKey, wrapped1, wrapped2);
					if (results[0].isSuccess() && results[1].isSuccess()) {
						byte[] decryptedSecret1 = results[0].getResult();
						byte[] decryptedSecret2 = results[1].getResult();

						System.out.println("Decrypted #1: " + BinUtils.toHexString(decryptedSecret1));
						System.out.println("Decrypted #2: " + BinUtils.toHexString(decryptedSecret2));

						if ((decryptedSecret1.length == random1.length)
								&& (decryptedSecret2.length == random1.length)) {
							if (BinUtils.binArrayElementsCompare(decryptedSecret1, 0, random1, 0,
									decryptedSecret1.length)
									&& BinUtils.binArrayElementsCompare(decryptedSecret2, 0, random2, 0,
											decryptedSecret2.length)) {
								System.err.println("Successfully decrypted all secrets !!!");
								System.exit(0);
							} else {
								System.err.println("Decrypted secrets do not match ...");
								System.exit(1);
							}
						} else {
							System.err.println("Decrypted secrets lengths do not match ...");
							System.exit(1);
						}
					} else {
						System.err.println("Unable to proced as wrapping failed on one or more devices ...");
						System.out.println("Wrap Status #1: " + BinUtils.toHexString(results[0].getSw()));
						System.out.println("Wrap Status #2: " + BinUtils.toHexString(results[1].getSw()));
						System.exit(1);
					}
				} else {
					System.err
							.println("Unable to proced as public key cannot be retrieved from one of the devices ...");
					System.exit(1);
				}
			} catch (CardException | NoSuchAlgorithmException | InvalidParameterSpecException
					| InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException
					| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
		} else {
			System.err.println("Unable to proced as less than 2 Hydra capable devices available ...");
			System.exit(1);
		}
	}
}