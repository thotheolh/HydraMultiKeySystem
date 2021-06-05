package hydra.hw.sc;

import javax.smartcardio.ResponseAPDU;

public class APDUResult {

	private byte[] result;
	private byte[] sw;
	private boolean isSuccess;

	public APDUResult(ResponseAPDU apdu) {
		setResult(DeviceHelper.getSuccessfulResponseData(apdu));
		setSw(DeviceHelper.getResponseSW(apdu));
		setSuccess(DeviceHelper.isSuccessfulResponse(apdu));
	}

	public APDUResult(byte[] result, byte[] sw, boolean isSuccess) {
		setResult(result);
		setSw(sw);
		setSuccess(isSuccess);
	}

	public byte[] getResult() {
		return result;
	}

	public void setResult(byte[] result) {
		this.result = result;
	}

	public byte[] getSw() {
		return sw;
	}

	public void setSw(byte[] sw) {
		this.sw = sw;
	}

	public boolean isSuccess() {
		return isSuccess;
	}

	public void setSuccess(boolean isSuccess) {
		this.isSuccess = isSuccess;
	}

}