package org.jrrevuelta.security.passwords;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * A SecuredPassword object represents the processed (digested) password from the user.<br>
 * <br>
 * All the other ancillary classes in the package use this object during its manipulation. Its storage
 * is responsibility of the user's system.<br>
 * <br>
 * According to the specification from the Recommendation [JRRevuelta-2019], the system needs to store
 * the 3 components (Derived Key, Counter and Encrypted Salt) that are contained in this object.<br>
 * <br>
 * Tomcat uses a <code>String</code> representation to recover the stored password and validation, so
 * this object can be instantiated from a string and can also be transformed into a recoverable string.<br>
 * <br>
 * The salt in this object is already encrypted, so even handling this object is secure.<br>
 * <br>
 * All the suggested parameters are used in the construction and manipulation of this object. They are
 * statically defined in the SecuredPasswordSettings class.<br>
 * <br>
 * [JRRevuelta-2019]: José Ramón Revuelta, Abril/2019, Recomendación, Almacenamiento seguro de contraseñas de usuarios.<br>
 * <br>
 * @author JRRevuelta
 */
public class SecuredPassword {
	
	private byte[] derivedKey;
	private byte[] salt;
	private int counter;
	
	private static final String SEPARATOR = ":";
	private static final int HEX_BASE = 16;
	private static final int UNSIGNED = 1;
	private static final int NUM_COMPONENTS = 3;
	private static final int SALT_COMPONENT = 0;
	private static final int COUNTER_COMPONENT = 1;
	private static final int DK_COMPONENT = 2;

	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");

	
	public SecuredPassword() {
		super();
		log.finest("JRR-SecurePassword: SecuredPassword model object instantiated.");
	}
	
	public SecuredPassword(String passwordString) {
		this();
		
		String[] parts = passwordString.split(SEPARATOR);
		if (parts.length != NUM_COMPONENTS) return;
		setSalt(new BigInteger(parts[SALT_COMPONENT],HEX_BASE).toByteArray());
		setCounter(new Integer(parts[COUNTER_COMPONENT]).intValue());
		setDerivedKey(new BigInteger(parts[DK_COMPONENT],HEX_BASE).toByteArray());
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
	
	public boolean isValid() {
		return  this.derivedKey !=null && this.derivedKey.length == 64
			&&  this.salt != null && this.salt.length == 64
			&&  this.counter > 0;
	}
	
	@Override
	public String toString() {
		
		String passwordString = new BigInteger(UNSIGNED, getSalt()).toString(HEX_BASE).toUpperCase();
		passwordString += SEPARATOR + Integer.toString(getCounter()) + SEPARATOR;
		passwordString += new BigInteger(UNSIGNED, getDerivedKey()).toString(HEX_BASE).toUpperCase();
		
		return passwordString;
	}
}
