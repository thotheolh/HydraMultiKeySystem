package hydra;

import hydra.crypto.HKDFRNG;
import hydra.crypto.RNGException;
import hydra.hw.sc.APDUResult;
import hydra.hw.sc.Device;
import hydra.hw.sc.DeviceManager;
import hydra.utils.BinUtils;
import hydra.utils.CryptoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;

public class StandaloneClient {
	public API api = null;
	private Device[] devices = null;
	private HKDFRNG rng = null;

	public StandaloneClient() throws CardException {
		devices = new Device[2];
		api = new API();
		rng = new HKDFRNG();
	}

	public void setDevice(int position, int deviceListSelectionPosition) {
		devices[position] = api.devices().get(deviceListSelectionPosition);
	}

	public void setDevice(int position, Device dev) {
		devices[position] = dev;
	}

	public void unsetDevice(int position) {
		devices[position] = null;
	}

	public boolean ready() {
		if (devices[0] != null && devices[1] != null) {
			return true;
		}

		return false;
	}

	public boolean encryptFile(String targetFilepath, String outputFilepath)
			throws CardException, InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException, RNGException {
		if (!ready()) {
			return false;
		}

		File inFile = new File(targetFilepath);

		if (!inFile.exists() || !inFile.isFile() || !inFile.canRead()) {
			return false;
		}

		File outFile = new File(outputFilepath);
		if (outFile.exists()) {
			outFile.delete();
		}

		if (!outFile.createNewFile()) {
			return false;
		}

		// Generate random ephemeral ECC keypair
		KeyPair kp = CryptoUtils.generateECKeyPair("secp256r1");
		MessageDigest hash = MessageDigest.getInstance("SHA-256");

		// MCS creation
		byte[] masterCryptoSeedLeft = CryptoUtils.getSecureRandomBytes(32);
		byte[] masterCryptoSeedRight = CryptoUtils.getSecureRandomBytes(32);
		byte[] fileEncryptionKey = CryptoUtils.getSecureRandomBytes(32);
		System.out.println("File Encryption Key: " + BinUtils.toHexString(fileEncryptionKey));

		// Wrap with hardware ECC public keys
		APDUResult res = null;
		byte[] hwDev1PublicKeyBytes = null;
		byte[] hwDev2PublicKeyBytes = null;
		res = api.rawGetPublicKey(devices[0]);
		if (res.isSuccess()) {
			hwDev1PublicKeyBytes = res.getResult();
			System.out.println("Encrypting to #1: " + BinUtils.toHexString(hwDev1PublicKeyBytes));
		}
		res = api.rawGetPublicKey(devices[1]);
		if (res.isSuccess()) {
			hwDev2PublicKeyBytes = res.getResult();
			System.out.println("Encrypting to #2: " + BinUtils.toHexString(hwDev2PublicKeyBytes));
		}

		// Create wrapped KEKs for Left and Right MCS splits
		byte[] hwSharedSecretLeftWrappedKEK = CryptoUtils.aesECBWrapKey(
				hash.digest(CryptoUtils.deriveECSharedSecret(true, hwDev1PublicKeyBytes, kp)), masterCryptoSeedLeft);
		hash.reset();
		byte[] hwSharedSecretRightWrappedKEK = CryptoUtils.aesECBWrapKey(
				hash.digest(CryptoUtils.deriveECSharedSecret(true, hwDev2PublicKeyBytes, kp)), masterCryptoSeedRight);
		hash.reset();

		// Wrap the File Encryption Key
		byte[] mcs = new byte[64];
		System.arraycopy(masterCryptoSeedLeft, 0, mcs, 0, 32);
		System.arraycopy(masterCryptoSeedRight, 0, mcs, 32, 32);
		rng.init(mcs, 0, 64);
		rng.debug();
		byte[] kek = new byte[32];
		rng.getRandom(kek, 0, 32);
		byte[] kekWrappedKey = CryptoUtils.aesECBWrapKey(kek, fileEncryptionKey);
		byte[] iv = CryptoUtils.getSecureRandomBytes(16);
		byte[] macKey = new byte[32];
		rng.getRandom(macKey, 0, 32);
		System.out.println("File MAC Key: " + BinUtils.toHexString(macKey));

		// Encrypt and MAC contents of the file with AES-CBC-PKCS5 and HMAC-SHA256
		Cipher cipher = CryptoUtils.getContentCryptoCipher(true, fileEncryptionKey, iv);
		Mac mac = CryptoUtils.getContentMac(macKey);
		long fileSize = inFile.length();
		long off = 0;
		int readLen = 0;
		FileInputStream fis = new FileInputStream(inFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		byte[] readBuff = new byte[4096];
		byte[] writeBuff = null;

		// Write header format: <Version -
		// 0100><EphemeralPubKeyLen><EphemeralPubKey><AsymmetricKeyCount -
		// byte><HWPubKey1Len - short><Hardware Public Key 1><HWPubKey2Len -
		// short><Hardware Public Key 2><HWWrapped1Len -
		// short><HWWrapped1><HWWrapped2Len - short><HWWrapped2><IVLen -
		// short><IV><WrappedKEKLen - short><WrappedKEK><Data><Mac>

		// Assemble format of the file with header format
		byte[] headerData = createHeader((short) 256, CryptoUtils.getPublicKeyBytes(kp, 32, true),
				CryptoUtils.getPublicKeyBytes(kp, 32, true), hwDev1PublicKeyBytes, hwDev2PublicKeyBytes,
				hwSharedSecretLeftWrappedKEK, hwSharedSecretRightWrappedKEK, iv, kekWrappedKey);

		System.out.println("IV: " + BinUtils.toHexString(iv));
		System.out.println("WCK: " + BinUtils.toHexString(kekWrappedKey));

		if (headerData == null) {
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		fos.write(headerData);
		fos.flush();

		// Handle file content
		while (off != fileSize) {
			readLen = fis.read(readBuff);
			if (readLen != -1) {
				writeBuff = CryptoUtils.processContentEncrypt(false, cipher, mac, readBuff, 0, readLen, null, 0, 0)[0];
				fos.write(writeBuff);
				fos.flush();
				off += readLen;
			}
		}

		// Finalize
		byte[][] finalDataBlocks = CryptoUtils.processContentEncrypt(true, cipher, mac, null, 0, 0, null, 0, 0);
		for (byte[] items : finalDataBlocks) {
			if (items != null) {
				fos.write(items);
				fos.flush();
			}
		}
		fis.close();
		fos.close();

		return true;
	}

	public boolean decryptFile(String targetFilepath, String outputFilepath, byte[] targetPrivateKey1,
			byte[] targetPrivateKey2) throws IOException, CardException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidParameterSpecException, InvalidKeySpecException, RNGException {
		byte[] ephemeralPubKey1 = null;
		byte[] ephemeralPubKey2 = null;
		byte[][] hwPubKeys = null;
		byte[] hwWrapped1 = null;
		byte[] hwWrapped2 = null;
		byte[] iv = null;
		byte[] wrappedContentKey = null;
		byte[] mac = null;
		APDUResult res = null;
		MessageDigest hash = MessageDigest.getInstance("SHA-256");

		if (targetPrivateKey1 != null && targetPrivateKey2 != null) {
			if (targetPrivateKey1.length != 32 || targetPrivateKey2.length != 32) {
				return false;
			}
		}

		File inFile = new File(targetFilepath);

		if (!inFile.exists() || !inFile.isFile() || !inFile.canRead()) {
			System.err.println("Input file not exists ...");
			return false;
		}

		File outFile = new File(outputFilepath);
		if (outFile.exists()) {
			outFile.delete();
		}

		if (!outFile.createNewFile()) {
			System.err.println("Output file failed to be created ...");
			return false;
		}

		// Check Mac before decryption
		// Parse header of target file
		long fileSize = inFile.length();
		long off = 0;
		int readLen = 0;
		FileInputStream fis = new FileInputStream(inFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		byte[] readBuff = null;
		boolean hasHeaderParsed = false;
		short version = -1;
		short sbuff = -1;
		APDUResult[] decryptedRes = null;

		// Header format: <Version -
		// 0100><EphemeralPubKeyLen><EphemeralPubKey><AsymmetricKeyCount -
		// byte><HWPubKey1Len - short><Hardware Public Key 1><HWPubKey2Len -
		// short><Hardware Public Key 2><HWWrapped1Len -
		// short><HWWrapped1><HWWrapped2Len - short><HWWrapped2><IVLen -
		// short><IV><WrappedKEKLen - short><WrappedKEK><Data><Mac>

		// Read version
		readBuff = new byte[2];
		fis.read(readBuff);
		version = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		off += 2;
		if (version != 256) {
			System.err.println("Incorrect version ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read amount of ephemeral key count
		int ephemKeyCount = (byte) (fis.read() & 0xFF);
		hwPubKeys = new byte[ephemKeyCount][];
		off++;
		if (ephemKeyCount < 1 || ephemKeyCount > 2) {
			System.err.println("Ephemeral key count [" + ephemKeyCount + "] is incorrect ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read ephemeral public key #1
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		ephemeralPubKey1 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(ephemeralPubKey1);

		// Read ephemeral public key #2
		if (ephemKeyCount == 2) {
			fis.read(readBuff);
			sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
			ephemeralPubKey2 = new byte[sbuff];
			off += sbuff + 2;
			fis.read(ephemeralPubKey2);
		}

		// Read amount of asymmetric key count
		int asymmKeyCount = (byte) (fis.read() & 0xFF);
		hwPubKeys = new byte[asymmKeyCount][];
		off++;
		if (asymmKeyCount < 1 || asymmKeyCount > 2) {
			System.err.println("Asymmetric key count [" + asymmKeyCount + "] is incorrect ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read HWPubKey1 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwPubKeys[0] = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwPubKeys[0]);

		// Read HWPubKey2 lenth and data
		if (asymmKeyCount == 2) {
			fis.read(readBuff);
			sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
			hwPubKeys[1] = new byte[sbuff];
			off += sbuff + 2;
			fis.read(hwPubKeys[1]);
		}

		// Read HWWrapped1 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwWrapped1 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwWrapped1);
		System.out.println("HWWrapped #1: " + BinUtils.toHexString(hwWrapped1));

		// Read HWWrapped2 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwWrapped2 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwWrapped2);
		System.out.println("HWWrapped #2: " + BinUtils.toHexString(hwWrapped2));

		// Read IV length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		iv = new byte[sbuff];
		off += sbuff + 2;
		fis.read(iv);

		// Read WrappedKEK length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		wrappedContentKey = new byte[sbuff];
		off += sbuff + 2;
		fis.read(wrappedContentKey);

		System.out.println("IV: " + BinUtils.toHexString(iv));
		System.out.println("WCK: " + BinUtils.toHexString(wrappedContentKey));

		// Read file MAC by restarting fileinputstream
		mac = new byte[32];
		fis.close();
		fis = new FileInputStream(inFile);
		fis.skip(fileSize - 32);
		fis.read(mac);
		fis.close();
		fis = new FileInputStream(inFile);

		if (targetPrivateKey1 != null && targetPrivateKey2 != null) {
			// Use both declared private keys to perform ECDH operation
			System.out.println("Using soft private keys ...");
			System.out.println("Ephem #1: " + BinUtils.toHexString(ephemeralPubKey1));
			System.out.println("Ephem #2: " + BinUtils.toHexString(ephemeralPubKey2));
			PrivateKey ecPrivateKey1 = CryptoUtils.getPrivateKey(targetPrivateKey1, "secp256r1");
			PrivateKey ecPrivateKey2 = CryptoUtils.getPrivateKey(targetPrivateKey2, "secp256r1");
			byte[] ssRaw1 = CryptoUtils.deriveECSharedSecret(true, ephemeralPubKey1, ecPrivateKey1);
			byte[] ssRaw2 = CryptoUtils.deriveECSharedSecret(true, ephemeralPubKey2, ecPrivateKey2);
			System.out.println("SS #1: " + BinUtils.toHexString(ssRaw1));
			System.out.println("SS #2: " + BinUtils.toHexString(ssRaw2));
			hash.reset();
			byte[] ssRawWrappingKey1 = hash.digest(ssRaw1);
			hash.reset();
			byte[] ssRawWrappingKey2 = hash.digest(ssRaw2);
			hash.reset();
			byte[] unwrappedMCS1 = CryptoUtils.aesECBUnwrapKey(ssRawWrappingKey1, hwWrapped1);
			byte[] unwrappedMCS2 = CryptoUtils.aesECBUnwrapKey(ssRawWrappingKey2, hwWrapped2);
			decryptedRes = new APDUResult[2];
			decryptedRes[0] = new APDUResult(unwrappedMCS1, new byte[] { (byte) 0x90, (byte) 0x00 }, true);
			decryptedRes[1] = new APDUResult(unwrappedMCS2, new byte[] { (byte) 0x90, (byte) 0x00 }, true);
		} else {
			// Derive keysets
			int foundDevices = 0;
			
			if (api.devices().size() >= asymmKeyCount) {
				for (int h = 0; h < hwPubKeys.length; h++) {
					byte[] hwPubKey = hwPubKeys[h];
					for (int i = 0; i < api.devices().size(); i++) {
						Device currDev = api.devices().get(i);
						res = api.rawGetPublicKey(currDev);
						if (res.isSuccess()) {
							byte[] hwPubKeyBytes = res.getResult();
							if (hwPubKey.length == hwPubKeyBytes.length) {
								if (BinUtils.binArrayElementsCompare(hwPubKey, 0, hwPubKeyBytes, 0, hwPubKey.length)) {
									System.out.println(
											"Found decrypting pub #" + h + ": " + BinUtils.toHexString(hwPubKeyBytes));
									setDevice(h, i);
									foundDevices++;
								}
							}
						}
					}
				}
				
				if (foundDevices < asymmKeyCount) {
					System.err.println("Relevant decryption keys not found ...");
					fis.close();
					fos.close();
					outFile.delete();
					return false;
				}
			} else {
				// Insufficient devices for activity
				fis.close();
				fos.close();
				outFile.delete();
				return false;
			}

			if (!ready()) {
				fis.close();
				fos.close();
				outFile.delete();
				return false;
			}
			decryptedRes = api.doECDHDecrypt(devices[0], devices[1], ephemeralPubKey1, ephemeralPubKey2, hwWrapped1,
					hwWrapped2);
		}

		if (decryptedRes == null) {
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		if (decryptedRes[0].isSuccess() && decryptedRes[1].isSuccess()) {
			byte[] mcsLeftBytes = decryptedRes[0].getResult();
			byte[] mcsRightBytes = decryptedRes[1].getResult();
			byte[] mcs = new byte[64];
			System.arraycopy(mcsLeftBytes, 0, mcs, 0, 32);
			System.arraycopy(mcsRightBytes, 0, mcs, 32, 32);
			rng.init(mcs, 0, 64);
			rng.debug();
			byte[] kek = new byte[32];
			rng.getRandom(kek, 0, 32);
			byte[] fileEncryptionKey = CryptoUtils.aesECBUnwrapKey(kek, wrappedContentKey);
			System.out.println("File Encryption Key: " + BinUtils.toHexString(fileEncryptionKey));
			byte[] macKey = new byte[32];
			rng.getRandom(macKey, 0, 32);
			System.out.println("File MAC Key: " + BinUtils.toHexString(macKey));
			byte[] computedMac = null;

			// Calculate MAC over the encrypted file content minus header and compare MAC in
			// file and computed MAC
			long macReadFileSize = fileSize - 32 - off;
			long macOff = 0;
			int readBuffPtr = 0;
			readBuff = new byte[4096];
			Mac macMech = CryptoUtils.getContentMac(macKey);

			fis.skip(off);
			while (macOff != macReadFileSize) {
				readBuff[readBuffPtr] = (byte) fis.read();
				readBuffPtr++;
				macOff++;

				if (readBuffPtr == 4096) {
					// Does a MAC update
//					System.out.println("MACing: " + BinUtils.toHexString(readBuff));
					macMech.update(readBuff);

					// Reset reading buffer pointer to 0 and read more data
					readBuffPtr = 0;
				}
			}

			// Flush the remaining data in buffer for Mac computation
			if (readBuffPtr != 0) {
//				System.out.println("MACing: " + BinUtils.toHexString(readBuff, 0, readBuffPtr));
				macMech.update(readBuff, 0, readBuffPtr);
			}

			// Finally compute Mac
			computedMac = macMech.doFinal();

			// Reset reading buffer pointer
			readBuffPtr = 0;

			// Compare computed mac vs. declared mac in file
			System.out.println("File MAC: " + BinUtils.toHexString(mac));
			System.out.println("Computed MAC: " + BinUtils.toHexString(computedMac));
			if (!BinUtils.binArrayElementsCompare(mac, 0, computedMac, 0, 32)) {
				System.err.println("MAC is incorrect ...");
				fis.close();
				fos.close();
				outFile.delete();
				return false;
			}

			// Reset fis once last time
			fis.close();
			fis = new FileInputStream(inFile);

			// Skip off amount of file header bytes
			fis.skip(off);
			off = 0;

			// Read data from offset to macReadFileSize for encrypted file content to be
			// decrypted
			Cipher cipher = CryptoUtils.getContentCryptoCipher(false, fileEncryptionKey, iv);
			byte[] writeBuff = null;
			while (off != macReadFileSize) {
				readBuff[readBuffPtr] = (byte) fis.read();
				readBuffPtr++;
				off++;

				if (readBuffPtr == 4096) {
					// Does a cipher update
//					System.out.println("Ciphering: " + BinUtils.toHexString(readBuff));
					writeBuff = cipher.update(readBuff);
					if (writeBuff != null) {
//						System.out.println("Plain Write Update: " + BinUtils.toHexString(writeBuff));
						fos.write(writeBuff);
						fos.flush();
					}

					// Reset reading buffer pointer to 0 and read more data
					readBuffPtr = 0;
				}
			}

			// Finalize
			writeBuff = cipher.doFinal(readBuff, 0, readBuffPtr);
			if (writeBuff != null) {
//				System.out.println("Plain Write Final: " + BinUtils.toHexString(writeBuff));
				fos.write(writeBuff);
				fos.flush();
			}
			fis.close();
			fos.close();
			return true;
		} else {
			System.err.println("HW ECDHDecrypt failed ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}
	}

	public boolean reencryptFile(String targetFilepath, String outputFilepath, byte[] recipientPublicKey1,
			byte[] recipientPublicKey2)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidParameterSpecException,
			InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, CardException, IOException {
		byte[] ephemeralPubKey1 = null;
		byte[] ephemeralPubKey2 = null;
		byte[][] hwPubKeys = null;
		byte[] hwWrapped1 = null;
		byte[] hwWrapped2 = null;
		byte[] iv = null;
		byte[] wrappedContentKey = null;
		APDUResult res = null;
		MessageDigest hash = MessageDigest.getInstance("SHA-256");

		// Check if at least one recipient public key is available
		if (recipientPublicKey1 == null && recipientPublicKey2 == null) {
			System.err.println("Recipient public keys not defined ...");
			return false;
		}

		// Check recipientPublicKey1
		if (recipientPublicKey1 != null) {
			if (recipientPublicKey1.length != 65 || recipientPublicKey1[0] != (byte) 0x04) {
				System.err.println("Recipient Public Key 1 is incorrect ...");
				return false;
			}
		}

		// Check recipientPublicKey2
		if (recipientPublicKey2 != null) {
			if (recipientPublicKey2.length != 65 || recipientPublicKey2[0] != (byte) 0x04) {
				System.err.println("Recipient Public Key 2 is incorrect ...");
				return false;
			}
		}

		File inFile = new File(targetFilepath);

		if (!inFile.exists() || !inFile.isFile() || !inFile.canRead()) {
			System.err.println("Input file not exists ...");
			return false;
		}

		File outFile = new File(outputFilepath);
		if (outFile.exists()) {
			outFile.delete();
		}

		if (!outFile.createNewFile()) {
			System.err.println("Output file failed to be created ...");
			return false;
		}

		// Check Mac before decryption
		// Parse header of target file
		long fileSize = inFile.length();
		long off = 0;
		int readLen = 0;
		FileInputStream fis = new FileInputStream(inFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		byte[] readBuff = null;
		boolean hasHeaderParsed = false;
		short version = -1;
		short sbuff = -1;

		// Header format: <Version -
		// 0100><EphemeralPubKeyLen><EphemeralPubKey><AsymmetricKeyCount -
		// byte><HWPubKey1Len - short><Hardware Public Key 1><HWPubKey2Len -
		// short><Hardware Public Key 2><HWWrapped1Len -
		// short><HWWrapped1><HWWrapped2Len - short><HWWrapped2><IVLen -
		// short><IV><WrappedKEKLen - short><WrappedKEK><Data><Mac>

		// Read version
		readBuff = new byte[2];
		fis.read(readBuff);
		version = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		off += 2;
		if (version != 256) {
			System.err.println("Incorrect version ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read amount of ephemeral key count
		int ephemKeyCount = (byte) (fis.read() & 0xFF);
		hwPubKeys = new byte[ephemKeyCount][];
		off++;
		if (ephemKeyCount < 1 || ephemKeyCount > 2) {
			System.err.println("Ephemeral key count [" + ephemKeyCount + "] is incorrect ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read ephemeral public key #1
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		ephemeralPubKey1 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(ephemeralPubKey1);
		System.out.println("Ephem #1: " + BinUtils.toHexString(ephemeralPubKey1));

		// Read ephemeral public key #2
		if (ephemKeyCount == 2) {
			fis.read(readBuff);
			sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
			ephemeralPubKey2 = new byte[sbuff];
			off += sbuff + 2;
			fis.read(ephemeralPubKey2);
			System.out.println("Ephem #2: " + BinUtils.toHexString(ephemeralPubKey2));
		}

		// Read amount of asymmetric key count
		int asymmKeyCount = (byte) (fis.read() & 0xFF);
		hwPubKeys = new byte[asymmKeyCount][];
		off++;
		if (asymmKeyCount < 1 || asymmKeyCount > 2) {
			System.err.println("Asymmetric key count [" + asymmKeyCount + "] is incorrect ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Read HWPubKey1 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwPubKeys[0] = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwPubKeys[0]);

		// If asymmKeyCount == 2, Read HWPubKey2 lenth and data
		if (asymmKeyCount == 2) {
			fis.read(readBuff);
			sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
			hwPubKeys[1] = new byte[sbuff];
			off += sbuff + 2;
			fis.read(hwPubKeys[1]);
		}

		// Read HWWrapped1 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwWrapped1 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwWrapped1);

		// Read HWWrapped1 length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		hwWrapped2 = new byte[sbuff];
		off += sbuff + 2;
		fis.read(hwWrapped2);

		// Read IV length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		iv = new byte[sbuff];
		off += sbuff + 2;
		fis.read(iv);

		// Read WrappedKEK length and data
		fis.read(readBuff);
		sbuff = BinUtils.bytesToShort(readBuff[0], readBuff[1]);
		wrappedContentKey = new byte[sbuff];
		off += sbuff + 2;
		fis.read(wrappedContentKey);

		// Derive keysets
		if (api.devices().size() >= asymmKeyCount) {
			for (int h = 0; h < hwPubKeys.length; h++) {
				byte[] hwPubKey = hwPubKeys[h];
				for (int i = 0; i < api.devices().size(); i++) {
					Device currDev = api.devices().get(i);
					res = api.rawGetPublicKey(currDev);
					if (res.isSuccess()) {
						byte[] hwPubKeyBytes = res.getResult();
						if (hwPubKey.length == hwPubKeyBytes.length) {
							if (BinUtils.binArrayElementsCompare(hwPubKey, 0, hwPubKeyBytes, 0, hwPubKey.length)) {
								System.out.println(
										"Found re-encrypting from #" + h + ": " + BinUtils.toHexString(hwPubKeyBytes));
								setDevice(h, i);
							}
						}
					}
				}
			}
		} else {
			// Insufficient devices for activity
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		// Call Re-encrypt API for Hydra devices
		if (!ready()) {
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}

		System.out.println("Recipient Public Key #1: " + BinUtils.toHexString(recipientPublicKey1));
		System.out.println("Recipient Public Key #2: " + BinUtils.toHexString(recipientPublicKey2));
		System.out.println("HWWrapped #1: " + BinUtils.toHexString(hwWrapped1));
		System.out.println("HWWrapped #2: " + BinUtils.toHexString(hwWrapped2));
		System.out.println("IV: " + BinUtils.toHexString(iv));
		System.out.println("WCK: " + BinUtils.toHexString(wrappedContentKey));
		APDUResult recryptedRes[] = api.doECDHReencrypt(devices[0], devices[1], ephemeralPubKey1, ephemeralPubKey2,
				recipientPublicKey1, recipientPublicKey2, hwWrapped1, hwWrapped2);
		if (recryptedRes[0].isSuccess() && recryptedRes[1].isSuccess()) {
			// Replace the Hydra devices re-wrapped MCS halves
			byte[] hwWrapped1Blob = recryptedRes[0].getResult();
			byte[] hwWrapped2Blob = recryptedRes[1].getResult();

			// Extract ephemeral public keys and wrapped key data from each returned blobs
			ephemeralPubKey1 = new byte[65];
			ephemeralPubKey2 = new byte[65];
			System.arraycopy(hwWrapped1Blob, 2, ephemeralPubKey1, 0, 65);
			System.arraycopy(hwWrapped2Blob, 2, ephemeralPubKey2, 0, 65);
			hwWrapped1 = new byte[hwWrapped1Blob.length - 67];
			hwWrapped2 = new byte[hwWrapped2Blob.length - 67];
			System.arraycopy(hwWrapped1Blob, 67, hwWrapped1, 0, hwWrapped1Blob.length - 67);
			System.arraycopy(hwWrapped2Blob, 67, hwWrapped2, 0, hwWrapped1Blob.length - 67);

			// Recreate new header
			byte[] headerData = createHeader((short) 256, ephemeralPubKey1, ephemeralPubKey2, recipientPublicKey1,
					recipientPublicKey2, hwWrapped1, hwWrapped2, iv, wrappedContentKey);

			// Output header
			if (headerData == null) {
				System.err.println("No header data found ...");
				return false;
			}

			fos.write(headerData);
			fos.flush();

			// Read content direct output
			int readBuffPtr = 0;
			readBuff = new byte[4096];

			// Read all except last 32 bytes of MAC and MAC encrypted contents
			while (off != fileSize) {
				readBuff[readBuffPtr] = (byte) fis.read();
				readBuffPtr++;
				off++;

				if (readBuffPtr == 4096) {
					// Does a write to output
//					System.out.println("Writing: " + BinUtils.toHexString(readBuff));
					fos.write(readBuff);
					fos.flush();

					// Reset reading buffer pointer to 0 and read more data
					readBuffPtr = 0;
				}
			}

			// Finalize
			if (readBuffPtr != 0) {
//				System.out.println("Writing: " + BinUtils.toHexString(readBuff, 0, readBuffPtr));
				fos.write(readBuff, 0, readBuffPtr);
				fos.flush();

			}
			// Close IO
			fis.close();
			fos.close();
			return true;
		} else {
			System.err.println("HW ECDHReencrypt failed ...");
			fis.close();
			fos.close();
			outFile.delete();
			return false;
		}
	}

	private byte[] createHeader(short version, byte[] ephemeralPublicKey1, byte[] ephemeralPublicKey2,
			byte[] targetPublicKey1, byte[] targetPublicKey2, byte[] targetAsymmKeyWrappedKEK1,
			byte[] targetAsymmKeyWrappedKEK2, byte[] iv, byte[] kekWrappedContentKey) {
		// Parameters checking
		if (!checkHeaders(version, ephemeralPublicKey1, ephemeralPublicKey2, targetPublicKey1, targetPublicKey2,
				targetAsymmKeyWrappedKEK1, targetAsymmKeyWrappedKEK2, iv, kekWrappedContentKey)) {
			return null;
		}

		byte[] headerData = null;
		int headerDataLength = 4; // 2 byte header, 1 byte ephemeral key count, 1 byte target key count
		int asymmKeyCount = 0;
		int ephemKeyCount = 0;
		int off = 0;

		if (ephemeralPublicKey1 != null) {
			headerDataLength += ephemeralPublicKey1.length + 2;
			ephemKeyCount++;
		}

		if (ephemeralPublicKey2 != null) {
			headerDataLength += ephemeralPublicKey2.length + 2;
			ephemKeyCount++;
		}

		if (targetPublicKey1 != null) {
			headerDataLength += targetPublicKey1.length + 2;
			asymmKeyCount++;
		}

		if (targetPublicKey2 != null) {
			headerDataLength += targetPublicKey2.length + 2;
			asymmKeyCount++;
		}

		if (targetAsymmKeyWrappedKEK1 != null) {
			headerDataLength += targetAsymmKeyWrappedKEK1.length + 2;
		}

		if (targetAsymmKeyWrappedKEK2 != null) {
			headerDataLength += targetAsymmKeyWrappedKEK2.length + 2;
		}

		headerDataLength += iv.length + kekWrappedContentKey.length + 4;
		headerData = new byte[headerDataLength];

		// Set header version
		BinUtils.shortToBytes(version, headerData, (short) 0);
		off += 2;

		// Set ephemeral key counts
		headerData[off] = (byte) (ephemKeyCount & 0xFF);
		off++;

		// Set ephemeral key #1
		if (ephemeralPublicKey1 != null) {
			BinUtils.shortToBytes((short) ephemeralPublicKey1.length, headerData, (short) off);
			off += 2;
			System.arraycopy(ephemeralPublicKey1, 0, headerData, off, ephemeralPublicKey1.length);
			off += ephemeralPublicKey1.length;
		}

		// Set ephemeral key #2
		if (ephemeralPublicKey2 != null) {
			BinUtils.shortToBytes((short) ephemeralPublicKey2.length, headerData, (short) off);
			off += 2;
			System.arraycopy(ephemeralPublicKey2, 0, headerData, off, ephemeralPublicKey2.length);
			off += ephemeralPublicKey2.length;
		}

		// Set target asymmetric key count
		headerData[off] = (byte) (asymmKeyCount & 0xFF);
		off++;

		// Set target public key key #1
		if (targetPublicKey1 != null) {
			BinUtils.shortToBytes((short) targetPublicKey1.length, headerData, (short) off);
			off += 2;
			System.arraycopy(targetPublicKey1, 0, headerData, off, targetPublicKey1.length);
			off += targetPublicKey1.length;
		}

		// Set target public key #2
		if (targetPublicKey2 != null) {
			BinUtils.shortToBytes((short) targetPublicKey2.length, headerData, (short) off);
			off += 2;
			System.arraycopy(targetPublicKey2, 0, headerData, off, targetPublicKey2.length);
			off += targetPublicKey2.length;
		}

		// Set target public key #1 wrapped MCS half
		BinUtils.shortToBytes((short) targetAsymmKeyWrappedKEK1.length, headerData, (short) off);
		off += 2;
		System.arraycopy(targetAsymmKeyWrappedKEK1, 0, headerData, off, targetAsymmKeyWrappedKEK1.length);
		off += targetAsymmKeyWrappedKEK1.length;

		// Set target public key #2 wrapped MCS half
		BinUtils.shortToBytes((short) targetAsymmKeyWrappedKEK2.length, headerData, (short) off);
		off += 2;
		System.arraycopy(targetAsymmKeyWrappedKEK2, 0, headerData, off, targetAsymmKeyWrappedKEK2.length);
		off += targetAsymmKeyWrappedKEK2.length;

		// Set File IV
		BinUtils.shortToBytes((short) iv.length, headerData, (short) off);
		off += 2;
		System.arraycopy(iv, 0, headerData, off, iv.length);
		off += iv.length;

		// Set Encrypted Content Key
		BinUtils.shortToBytes((short) kekWrappedContentKey.length, headerData, (short) off);
		off += 2;
		System.arraycopy(kekWrappedContentKey, 0, headerData, off, kekWrappedContentKey.length);
		off += kekWrappedContentKey.length;
		return headerData;
	}

	private boolean checkHeaders(short version, byte[] ephemeralPublicKey1, byte[] ephemeralPublicKey2,
			byte[] targetPublicKey1, byte[] targetPublicKey2, byte[] targetAsymmKeyWrappedKEK1,
			byte[] targetAsymmKeyWrappedKEK2, byte[] iv, byte[] kekWrappedContentKey) {
		if (version != 256) {
			return false;
		}

		if (ephemeralPublicKey1 == null && ephemeralPublicKey2 == null) {
			return false;
		}

		if (targetPublicKey1 == null && targetPublicKey2 == null) {
			return false;
		}

		if (targetAsymmKeyWrappedKEK1 == null && targetAsymmKeyWrappedKEK2 == null) {
			return false;
		}

		if (iv == null) {
			return false;
		}

		if (iv.length != 16) {
			return false;
		}

		if (kekWrappedContentKey == null) {
			return false;
		}

		if (kekWrappedContentKey.length != 32) {
			return false;
		}

		if (ephemeralPublicKey1 != null) {
			if (ephemeralPublicKey1.length != 65 || ephemeralPublicKey1[0] != (byte) 0x04) {
				return false;
			}
		}

		if (ephemeralPublicKey2 != null) {
			if (ephemeralPublicKey2.length != 65 || ephemeralPublicKey2[0] != (byte) 0x04) {
				return false;
			}
		}

		if (targetPublicKey1 != null) {
			if (targetPublicKey1.length != 65 || targetPublicKey1[0] != (byte) 0x04) {
				return false;
			}
		}

		if (targetPublicKey2 != null) {
			if (targetPublicKey2.length != 65 || targetPublicKey2[0] != (byte) 0x04) {
				return false;
			}
		}

		if (targetAsymmKeyWrappedKEK1 != null) {
			if (targetAsymmKeyWrappedKEK1.length != 32) {
				return false;
			}
		}

		if (targetAsymmKeyWrappedKEK2 != null) {
			if (targetAsymmKeyWrappedKEK2.length != 32) {
				return false;
			}
		}

		return true;
	}

}
