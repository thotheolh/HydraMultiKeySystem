package hydra;

import java.security.PrivateKey;
import java.security.PublicKey;

import hydra.hw.sc.Device;

public class HydraKey {

	private String containerName;
	private String keyName;
	private PublicKey pubKey;
	private PrivateKey privKey;
	private Device devRef;

	public HydraKey(String containerName, String keyName, Device subjectDevice) {
		setContainerName(containerName);
		setKeyName(keyName);
		setDevice(subjectDevice);
	}

	public HydraKey(String containerName, String keyName, PublicKey subjectPublicKey, PrivateKey subjectPrivateKey) {
		setContainerName(containerName);
		setKeyName(keyName);
		setPrivateKey(subjectPrivateKey);
		setPublicKey(subjectPublicKey);
	}

	public String getContainerName() {
		return containerName;
	}

	public void setContainerName(String containerName) {
		this.containerName = containerName;
	}

	public String getKeyName() {
		return keyName;
	}

	public void setKeyName(String keyName) {
		this.keyName = keyName;
	}

	public boolean isDevice() {
		if (devRef != null) {
			return true;
		}
		
		return false;
	}

	private void setDevice(Device device) {
		this.devRef = device;
	}
	
	public Device getDevice() {
		return this.devRef;
	}

	public PublicKey getPublicKey() {
		return pubKey;
	}

	private void setPublicKey(PublicKey pubKey) {
		this.pubKey = pubKey;
	}

	public PrivateKey getPrivateKey() {
		return privKey;
	}

	private void setPrivateKey(PrivateKey privKey) {
		this.privKey = privKey;
	}	

	public String toString() {
		return getContainerName() + " - " + getKeyName();
	}

}
