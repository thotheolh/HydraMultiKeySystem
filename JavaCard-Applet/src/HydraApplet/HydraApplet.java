package HydraApplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class HydraApplet extends Applet {

    private static ECPrivateKey ecPrivKey;
    private static ECPublicKey ecPubKey;
    private static KeyPair kp;
    private static ECPrivateKey tmpEcPrivKey;
    private static ECPublicKey tmpEcPubKey;
    private static KeyPair tmpKp;
    private static KeyAgreement ecdh = null;
    private static MessageDigest hash = null;
    private static Cipher aesCipher = null;
    private static ECC eccAlgo;
    private static AESKey aesKey = null;
    private static byte[] b0 = null;

    public static final byte CLA = (byte) 0xB0;
    public static final byte INS_GET = (byte) 0xCA;
    public static final byte INS_CRYPT = (byte) 0x2A;
    public static final byte P1_DECRYPT = (byte) 0x01;
    public static final byte P1_RECRYPT = (byte) 0x02;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        eccAlgo = new ECC();
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        b0 = JCSystem.makeTransientByteArray((short) 65, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        tmpEcPrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_EC_FP_256, false);
        tmpEcPubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256,
                false);
        new HydraApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            if (ecPrivKey == null && ecPubKey == null) {
                ecPrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                        KeyBuilder.LENGTH_EC_FP_256, false);
                ecPubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256,
                        false);
                eccAlgo.setCurveParameters(ecPrivKey);
                eccAlgo.setCurveParameters(ecPubKey);
                kp = new KeyPair(ecPubKey, ecPrivKey);
                kp.genKeyPair();
            }
            return;
        }

        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (ecPrivKey == null || ecPubKey == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET:
                short keyLen = ecPubKey.getW(buf, (short) 0);
                apdu.setOutgoingAndSend((short) 0, keyLen);
                break;
            case INS_CRYPT:
                byte p1 = buf[ISO7816.OFFSET_P1];
                byte hashAlgo = buf[ISO7816.OFFSET_P2];
                short len = apdu.setIncomingAndReceive();

                if (hashAlgo != MessageDigest.ALG_SHA_256) {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }

                if (p1 == P1_DECRYPT) {
                    // Input Data Format: <0100 protocol version><65 byte ECC-P256R1 uncompressed
                    // public key><AES-256-ECB encrypted secret up to 64 bytes long>

                    if ((len < 99) || (len > 131)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }

                    if (!(buf[apdu.getOffsetCdata()] == (byte) 0x01
                            && buf[(short) (apdu.getOffsetCdata() + 1)] == (byte) 0x00)) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }

                    len = keyDecrypt(buf, (short) (apdu.getOffsetCdata() + 2), (short) (len - 2), b0, (short) 0, b0,
                            (short) 0, hashAlgo);
                    Util.arrayCopyNonAtomic(b0, (short) 0, buf, (short) 0, len);
                    Util.arrayFillNonAtomic(b0, (short) 0, (short) b0.length, (byte) 0x00);
                    apdu.setOutgoingAndSend((short) 0, len);
                } else if (p1 == P1_RECRYPT) {
                    // Input Data Format: <0100 protocol version><65 byte ECC-P256R1 wrapping
                    // uncompressed public key><AES-256-ECB encrypted secret up to 64 bytes long><65
                    // byte ECC-P256R1 target uncompressed>
                    if ((len < 164) || (len > 196)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }

                    if (!(buf[apdu.getOffsetCdata()] == (byte) 0x01
                            && buf[(short) (apdu.getOffsetCdata() + 1)] == (byte) 0x00)) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }

                    // Decrypt
                    len = keyDecrypt(buf, (short) (apdu.getOffsetCdata() + 2), (short) (len - 67), b0, (short) 0, b0,
                            (short) 0, hashAlgo);

                    // Compact decrypted secret onto apdu buffer
                    Util.arrayCopyNonAtomic(b0, (short) 0, buf, (short) (apdu.getOffsetCdata() + 67), len);

                    // Bring target public key for encryption forward to replace wrapping public key
                    Util.arrayCopyNonAtomic(buf, (short) (apdu.getOffsetCdata() + 67 + len), buf,
                            (short) (apdu.getOffsetCdata() + 2), (short) 65);

                    // Encrypt
                    len = keyEncrypt(buf, (short) (apdu.getOffsetCdata() + 2), (short) (65 + len), b0, (short) 0, b0,
                            (short) 0, hashAlgo);

                    // Format return result <0100 protocol version><65 byte ECC-P256R1 uncompressed
                    // public key><AES-256-ECB encrypted secret up to 64 bytes long>
                    tmpEcPubKey.getW(buf, (short) (apdu.getOffsetCdata() + 2));
                    Util.arrayCopyNonAtomic(b0, (short) 0, buf, (short) (apdu.getOffsetCdata() + 67), len);
                    Util.arrayFillNonAtomic(b0, (short) 0, (short) b0.length, (byte) 0x00);
                    apdu.setOutgoingAndSend(apdu.getOffsetCdata(), (short) (67 + len));
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private short keyDecrypt(byte[] input, short off, short len, byte[] output, short outOff, byte[] buff,
            short buffOff, byte hashAlgo) {
        ecdh.init(ecPrivKey);
        short shareLen = ecdh.generateSecret(input, off, (short) 65, buff, (short) (buffOff + 32));
        short kekLen = secretHash(buff, (short) (buffOff + 32), shareLen, buff, buffOff);
        aesKey.setKey(buff, buffOff);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        return aesCipher.doFinal(input, (short) (65 + off), (short) (len - 65), output, outOff);
    }

    private short keyEncrypt(byte[] input, short off, short len, byte[] output, short outOff, byte[] buff,
            short buffOff, byte hashAlgo) {
        tmpEcPrivKey.clearKey();
        tmpEcPubKey.clearKey();
        eccAlgo.setCurveParameters(tmpEcPrivKey);
        eccAlgo.setCurveParameters(tmpEcPubKey);
        tmpKp = new KeyPair(tmpEcPubKey, tmpEcPrivKey);
        tmpKp.genKeyPair();
        ecdh.init(tmpEcPrivKey);
        short shareLen = ecdh.generateSecret(input, off, (short) 65, buff, (short) (buffOff + 32));
        short kekLen = secretHash(buff, (short) (buffOff + 32), shareLen, buff, buffOff);
        aesKey.setKey(buff, buffOff);
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        short resLen = 0;
        resLen = aesCipher.doFinal(input, (short) (65 + off), (short) (len - 65), output, outOff);
        return resLen;
    }

    private short secretHash(byte[] input, short off, short len, byte[] output, short outOff) {
        hash.reset();
        return hash.doFinal(input, off, len, output, outOff);
    }

}
