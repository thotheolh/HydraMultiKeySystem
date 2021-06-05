package hydra;

public class Constants {
	public static final byte[] APDU_SELECT = { (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00 };
	public static final byte PRELOAD_MODE_CLEAR = (byte) 0xFF;
	public static final byte PRELOAD_MODE_UPLOAD = (byte) 0x00;
	public static final byte PRELOAD_MODE_LENGTH = (byte) 0x01;
	public static final byte PRELOAD_MODE_DOWNLOAD = (byte) 0x02;
	public static final byte IMPORT_EXPORT_MODE_FP_SETUP = (byte) 0x01;
	public static final byte IMPORT_EXPORT_MODE_IMPORT = (byte) 0x02;
	public static final byte IMPORT_EXPORT_MODE_EXPORT = (byte) 0x03;
	public static final byte IMPORT_EXPORT_MODE_VIEW = (byte) 0x00;
	public static final byte[] X509_GEN_CERT_RSA = {(byte) 0x01, (byte) 0x00};
	public static final byte[] X509_GEN_CERT_ECC = {(byte) 0x01, (byte) 0x01};
	public static final byte[] X509_GEN_CSR_RSA = {(byte) 0x01, (byte) 0x02};
	public static final byte[] X509_GEN_CSR_ECC = {(byte) 0x01, (byte) 0x03};
	public static final byte[] X509_IMPORT_CERT_RSA = {(byte) 0x02, (byte) 0x00};
	public static final byte[] X509_IMPORT_CERT_ECC = {(byte) 0x02, (byte) 0x01};
	public static final byte[] X509_EXPORT_CERT_RSA = {(byte) 0x03, (byte) 0x00};
	public static final byte[] X509_EXPORT_CERT_ECC = {(byte) 0x03, (byte) 0x01};
	public static final byte[] X509_EXPORT_CERT_LEN = {(byte) 0x03, (byte) 0x02};
}