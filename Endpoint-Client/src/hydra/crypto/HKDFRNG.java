package hydra.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import hydra.utils.BinUtils;
import hydra.utils.CryptoUtils;

public class HKDFRNG {

	private Mac mac = null;
	private byte[] salt = null;
	private byte[] seed = null;
	private byte[] prk = null;
	private byte[] randOutBuff = null;
	private byte[] info = null;
	private int randOutPtr = 0;
	private long randCycle = 0;
	private long randMaxCycle = Long.MAX_VALUE - 1;
	private int randOutBuffLen = 255 * 32; // As prescribed in RFC-5869 for SHA256 based hash for max buffer length

	public HKDFRNG() {
		salt = new byte[32];
		prk = new byte[32];
		randOutBuff = new byte[randOutBuffLen];
	}

	public void init() throws InvalidKeyException, NoSuchAlgorithmException, RNGException {
		clear();
		this.seed = CryptoUtils.getSecureRandomBytes(32);
		mac = CryptoUtils.getContentMac(seed);
		Arrays.fill(this.seed, (byte) 0x00);
		this.seed = null;
		this.prk = mac.doFinal(this.salt);
		hkdfPopulateRandom();
	}

	public void init(byte[] seed, int seedOff, int seedLen)
			throws InvalidKeyException, NoSuchAlgorithmException, RNGException {
		clear();
		this.seed = new byte[seedLen];
		System.arraycopy(seed, seedOff, this.seed, 0, seedLen);
		mac = CryptoUtils.getContentMac(seed);
		Arrays.fill(this.seed, (byte) 0x00);
		this.seed = null;
		this.prk = mac.doFinal(this.salt);
		hkdfPopulateRandom();
	}

	public void init(byte[] seed, int seedOff, int seedLen, byte[] salt, int saltOff)
			throws InvalidKeyException, NoSuchAlgorithmException, RNGException {
		clear();
		this.seed = new byte[seedLen];
		System.arraycopy(seed, seedOff, this.seed, 0, seedLen);
		System.arraycopy(salt, saltOff, this.salt, 0, 32);
		mac = CryptoUtils.getContentMac(seed);
		Arrays.fill(this.seed, (byte) 0x00);
		this.seed = null;
		this.prk = mac.doFinal(this.salt);
		hkdfPopulateRandom();
	}

	public void getRandom(byte[] output, int outOff, int outLen) throws RNGException, InvalidKeyException {
		int outCopied = 0;

		// Check if anymore output length not fulfilled
		while (outCopied != outLen) {
			// Check if available bytes in random buffer for output
			if (randOutPtr >= randOutBuff.length) {
				// No available bytes in random buffer for output, make more random
				hkdfPopulateRandom();

				// Reset random buffer pointer
				randOutPtr = 0;
			}

			// Output random
			output[outOff + outCopied] = randOutBuff[randOutPtr];
			outCopied++;
			randOutPtr++;
		}
	}

	private void hkdfPopulateRandom() throws RNGException, InvalidKeyException {
		if (requireInit()) {
			// Throw reseed exception
			throw new RNGException("Resseding of HKDFRNG required");
		}

		// Generate more random materials
		// Set info
		byte[] ti = new byte[32];
		int randCopyPtr = 0;
		info = BinUtils.longToBytes(randCycle);
		for (int i = 1; i <= 255; i++) {
			// randomSegmentBuff = HMAC-Hash( PRK, ti | info | i )
			// ti = randomSegmentBuff
			byte[] input = new byte[ti.length + info.length + 1];
			System.arraycopy(ti, 0, input, 0, ti.length);
			System.arraycopy(info, 0, input, ti.length, info.length);
			input[ti.length + info.length] = (byte) (i & 0xFF);
			mac.reset();
			mac.init(new SecretKeySpec(prk, "HmacSHA256"));
			ti = mac.doFinal(input);
			System.arraycopy(ti, 0, randOutBuff, randCopyPtr, ti.length);
			randCopyPtr += ti.length;
		}
		randCycle++;
	}

	public boolean requireInit() {
		if (randCycle < randMaxCycle) {
			return false;
		}

		return true;
	}

	public void clear() {
		if (mac != null) {
			mac.reset();
		}
		if (salt != null) {
			Arrays.fill(salt, (byte) 0x00);
		}
		if (prk != null) {
			Arrays.fill(prk, (byte) 0x00);
		}
		if (randOutBuff != null) {
			Arrays.fill(randOutBuff, (byte) 0x00);
		}
		randOutPtr = 0;
		randCycle = 0;
	}

	public void debug() {
		System.out.println("State: " + BinUtils.toHexString(randOutBuff));
		System.out.println("RandBuffPtr: " + randOutPtr);
		System.out.println("RandCycle: " + randCycle);
	}

	public static void main(String[] args) {
		HKDFRNG rng = new HKDFRNG();
		byte[] random = new byte[256];
		try {
			rng.init();
			rng.getRandom(random, 0, random.length);
			System.out.println("Random:" + BinUtils.toHexString(random));
			rng.debug();
			rng.getRandom(random, 0, random.length);
			System.out.println("Random: " + BinUtils.toHexString(random));
		} catch (InvalidKeyException | NoSuchAlgorithmException | RNGException e) {
			e.printStackTrace();
		}
	}

}