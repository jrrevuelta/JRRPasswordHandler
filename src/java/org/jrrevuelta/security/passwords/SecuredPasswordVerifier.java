package org.jrrevuelta.security.passwords;



import java.io.UnsupportedEncodingException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * A secured password verifier is used to test a claimed password against a previously stored secured 
 * password according to the protocols and algorithms described in the Reccomendation [JRRevuelta-2019].<br>
 * <br>
 * A verifier object can be created and initialized with a <code>SecuredPassword</code> object, or with the 
 * three components separately. But in order to start a validation, all three components must be set.<br>
 * <br>
 * If the three components are not correctly set, the verifier will throw an <code>IllegalStateException</code>.
 * The best way to create the verifier object is with the constructor that indicates the appropriate 
 * <code>SecuredPassword</code> object.<br>
 * <br>
 * This verifier object can be used to check multiple times a password (or different passwords), of course 
 * it would only evaluate as correct for the right password.<br>
 * <br>
 * [JRRevuelta-2019]: José Ramón Revuelta, Abril/2019, Recomendación, Almacenamiento seguro de contraseñas de usuarios.<br>
 * <br>
 * @author JRRevuelta
 */
public class SecuredPasswordVerifier {
	
	private byte[] derivedKey;
	private byte[] salt;
	private int counter;
	
	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");
	
	
	public SecuredPasswordVerifier() {
		super();
		log.finest("JRR-Security: SecuredPasswordVerifier object instantiated.");
	}
	
	public SecuredPasswordVerifier(SecuredPassword initPassword) {
		this();
		if (initPassword.isValid()) {
			this.derivedKey = initPassword.getDerivedKey();
			this.salt = decryptSalt(initPassword.getSalt());
			this.counter = initPassword.getCounter();
		}
	}
	
	
	public byte[] getDerivedKey() {
		return derivedKey;
	}
	
	public void setDerivedKey(byte[] derivedKey) {
		this.derivedKey = derivedKey;
	}
	
	public byte[] getSalt() {
		return salt;
	}
	
	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
	
	public int getCounter() {
		return counter;
	}
	
	public void setCounter(int counter) {
		this.counter = counter;
	}
	
	
	/**
	 * Verifies a given (claimed) password against the stored password that was used to initialize
	 * this object. It returns <code>true</code> only if the claimed password is correct (if it is
	 * the same as the one that was used to generate the stored secured password).
	 * 
	 * @param claimedPassword a <code>String</code> containing a clear text password that is to be tested
	 * with the stored secured password. 
	 * @return <code>true</code> if the claimed password is the same as the stored secured password. 
	 * Otherwise <code>false</code>.
	 * @throws IllegalStateException when the verifier has not been completely initialized with all 
	 * three components of the secured password, or with an appropriate <code>SecuredPassword</code> object
	 * prior to the verification of a claimed password.
	 */
	public boolean verifyPassword(String claimedPassword) throws IllegalStateException {
		
		if (this.derivedKey == null || this.salt == null || this.counter == 0) {
			throw new IllegalStateException("JRR-Security: All three components of a SecuredPassword must be set before verification.");
		}
		if (claimedPassword == null || claimedPassword.isEmpty()) return false;
		
		boolean verification = false;
		try {
			byte[] claimedPasswordBytes = claimedPassword.getBytes(SecuredPasswordSettings.passwordEncoding);
			byte[] claimedDK = pbkdf2(claimedPasswordBytes, this.salt, this.counter);
			verification = compareDerivedKeys(this.derivedKey, claimedDK);
			
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (UnsupportedEncodingException e) {
			log.warning("JRR-Security (Unsupported configuration): Password cannot be verified: " + e.getMessage());
		}
		return verification;
	}
	
	
	private byte[] decryptSalt(byte[] salt) {
		
		byte[] decryptedSalt = null;
		try {
			SecretKeySpec saltEncryptionKeySpec = new SecretKeySpec(SecuredPasswordSettings.saltEncryptionKeyBytes(), "AES");
			Cipher saltCipher = Cipher.getInstance(SecuredPasswordSettings.saltEncryptionCipher);
			saltCipher.init(Cipher.DECRYPT_MODE, saltEncryptionKeySpec);
			decryptedSalt = saltCipher.doFinal(salt);
			
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (NoSuchAlgorithmException |
				 NoSuchPaddingException |
				 InvalidKeyException |
				 IllegalBlockSizeException |
				 BadPaddingException e) {    
			log.warning("JRR-Security (Unsupported configuration): Exception while decrypting password salt: " + e.getMessage());
		}

		return decryptedSalt;    // returns null if any exceptions are raised during decryption
	}
	
	
	private byte[] pbkdf2(byte[] password, byte[] salt, int counter) {
		
		byte[] dk = new byte[SecuredPasswordSettings.derivedKeySizeBytes];

		try {
			// Prepare underlying PRF (pseudo-random function)... seed it with 'password' as the key to use in every iteration
			Mac hmac = Mac.getInstance(SecuredPasswordSettings.prf);
			hmac.init(new SecretKeySpec(password, "RAW"));
			
			// Initialize the derivedKey vector with all ZERO bits and the first 'macText' to use will be 'salt'
			for (int i=0; i<dk.length; i++) {
				dk[i] = 0x00;
			}
			byte[] macText = salt;

			// Perform the series of PRFs 'count' times, starting with initial state of 'macText' ('salt')
			for (int i=0; i<counter; i++) {
				byte[] u = hmac.doFinal(macText);
				for (int j=0; j<dk.length; j++) {
					dk[j] ^= u[j];
				}
				macText = u;
			}
			
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			log.warning("JRR-Security (Unsupported configuration): Exception while deriving key from password: " + e.getMessage());
		}   
		
		return dk;
	}
	
	
	private boolean compareDerivedKeys(byte[] original, byte[] claimed) {
		
		boolean comparison = true;
		if (original.length == claimed.length) {
			for (int i=0; i<original.length; i++) {
				if (original[i] != claimed[i]) {
					comparison = false;
					break;
				}
			}
		} else {
			comparison = false;
		}
		
		return comparison;
	}

	
}
