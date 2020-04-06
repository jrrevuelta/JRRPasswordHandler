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
		this.derivedKey = initPassword.getDerivedKey();
		this.salt = decryptSalt(initPassword.getSalt());
		this.counter = initPassword.getCounter();
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
	
	
	public boolean verifyPassword(String claimedPassword) {
		
		boolean verification = false;
		try {
			byte[] claimedPasswordBytes = claimedPassword.getBytes(SecuredPasswordSettings.passwordEncoding);
			byte[] claimedDK = pbkdf2(claimedPasswordBytes, this.salt, this.counter);
			verification = compareDerivedKeys(this.derivedKey, claimedDK);
			
		} catch (UnsupportedEncodingException e) {
			log.warning("JRR-Security: Password cannot be verified: " + e.getMessage());
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
			
		// None of these exceptions should be raised (based on input, only by bad configuration)
		} catch (NoSuchAlgorithmException |
				 NoSuchPaddingException |
				 InvalidKeyException |
				 IllegalBlockSizeException |
				 BadPaddingException e) {    
			log.warning("JRR-Security: Exception while decrypting password salt: " + e.getMessage());
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
			
		// None of these exceptions should be raised (based on input, only by bad configuration)
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			log.warning("JRR-Security: Exception while deriving key from password: " + e.getMessage());
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
