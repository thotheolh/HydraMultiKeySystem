package hydra.hw.sc;

import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class DeviceManager {

	private volatile static DeviceManager instance = null;
	private volatile TerminalHandler termMan = null;
	public static final String DEFAULT_CARD_PROTO = TerminalHandler.CARD_PROTO_ANY;
	private volatile ArrayList<Device> devices = new ArrayList<>();
	private byte[] aid = { (byte) 0x48, (byte) 0x59, (byte) 0x44, (byte) 0x52, (byte) 0x41, (byte) 0x30, (byte) 0x31,
			(byte) 0x30, (byte) 0x30 };

	protected DeviceManager(boolean isLogOut) throws CardException {
		termMan = new TerminalHandler();
		refreshDevices(isLogOut);
	}

	public static DeviceManager getInstance() throws CardException {
		if (instance == null) {
			instance = new DeviceManager(true);
		}

		return instance;
	}
	
	public static DeviceManager getInstance(boolean isLogOut) throws CardException {
		if (instance == null) {
			instance = new DeviceManager(isLogOut);
		}

		return instance;
	}

	public void refreshDevices(boolean logOut) throws CardException {
		if (logOut) {
			System.out.println("Refreshing devices ...");
		}
		disconnectAllExistingDevices();
		termMan.loadDefaultTerminal();
		devices.clear();
		List<CardTerminal> terminals = termMan.getTerminals();
		if (logOut) {
			System.out.println("Found terminals: " + terminals.size());
		}
		for (int i = 0; i < terminals.size(); i++) {
			if (logOut) {
				System.out.println("Querying terminal: " + terminals.get(i).getName());
			}
			Card tempCard = termMan.getCard(DEFAULT_CARD_PROTO, i);
			Device tempDevice = new Device(tempCard, terminals.get(i).getName());
			if (tempDevice.connect(aid)) {
				devices.add(tempDevice);
			}
		}
	}

	public void disconnectAllExistingDevices() throws CardException {
		if (devices.size() > 0) {
			for (Device tempDevice : devices) {
				tempDevice.disconnect();
			}
		}
	}

	public int getDevicesCount() {
		return devices.size();
	}

	public ArrayList<Device> getDevices() {
		return devices;
	}

	public Device getDevice(int i) {
		return devices.get(i);
	}

	public byte[] getAid() {
		return aid;
	}

	public void setAid(byte[] aid) {
		this.aid = aid;
	}
}
