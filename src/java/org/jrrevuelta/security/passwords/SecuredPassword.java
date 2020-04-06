package org.jrrevuelta.security.passwords;

import java.math.BigInteger;
import java.util.logging.Logger;

public class SecuredPassword {
	
	private byte[] derivedKey;
	private byte[] salt;
	private int counter;

	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");

	
	public SecuredPassword() {
		super();
		log.finest("JRR-SecurePassword: SecuredPassword model object instantiated.");
	}
	
	public SecuredPassword(String passwordString) {
		this();
		
		String[] parts = passwordString.split(":");
		if (parts.length != 3) return;
		setSalt(new BigInteger(parts[0],16).toByteArray());
		setCounter(new Integer(parts[1]).intValue());
		setDerivedKey(new BigInteger(parts[2],16).toByteArray());
	}
	
	public SecuredPassword(byte[] derivedKey, byte[] salt, int counter) {
		this();
		
		setDerivedKey(derivedKey);
		setSalt(salt);
		setCounter(counter);
	}
	
	
	public byte[] getDerivedKey() {
		return derivedKey;
	}
	public void setDerivedKey(byte[] derivedKey) {
		
		if (derivedKey.length > SecuredPasswordSettings.derivedKeySizeBytes) {
			byte[] b2 = new byte[SecuredPasswordSettings.derivedKeySizeBytes];
			for (int i=0; i<SecuredPasswordSettings.derivedKeySizeBytes; i++) {
				b2[i] = derivedKey[i+1];
			}
			derivedKey = b2;
		}

		this.derivedKey = derivedKey;
	}
	
	public byte[] getSalt() {
		return salt;
	}
	public void setSalt(byte[] salt) {
		
		if (salt.length > SecuredPasswordSettings.saltSizeBytes) {
			byte[] b2 = new byte[SecuredPasswordSettings.saltSizeBytes];
			for (int i=0; i<SecuredPasswordSettings.saltSizeBytes; i++) {
				b2[i] = salt[i+1];
			}
			salt = b2;
		}

		this.salt = salt;
	}
	
	public int getCounter() {
		return counter;
	}
	public void setCounter(int counter) {
		this.counter = counter;
	}
	
	@Override
	public String toString() {
		
		String passwordString = new BigInteger(1, getSalt()).toString(16).toUpperCase();
		passwordString += ":" + Integer.toString(getCounter()) + ":";
		passwordString += new BigInteger(1, getDerivedKey()).toString(16).toUpperCase();
		
		return passwordString;
	}
}
