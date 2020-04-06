package org.jrrevuelta.security.passwords;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class SecuredPasswordGenerator {
	
	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");

	
	public SecuredPassword generateNewSecuredPassword(String originalPassword) {

		byte[] derivedKey = null;
		byte[] salt = null;
		int counter = 0;
		SecureRandom random = new SecureRandom();
		
		// Generate salt... random sequence of 512 bits (64 bytes)
		salt = new byte[SecuredPasswordSettings.saltSizeBytes];
		random.nextBytes(salt);
		
		// Generate counter... random number within a limit
		counter = random.nextInt(SecuredPasswordSettings.countLimit);

		try {
			byte[] passwordBytes = originalPassword.getBytes(SecuredPasswordSettings.passwordEncoding);
			derivedKey = pbkdf2(passwordBytes, salt, counter);   // Generate the DK = PBKDF2(P, S, c)
		
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (UnsupportedEncodingException e) {
			log.severe("JRR-Security (Unsupported configuration): Exception while deriving key from password: " + e.getMessage());
		}
		
		SecuredPassword password = new SecuredPassword(derivedKey, encryptSalt(salt), counter);

		return password;   // Password invalid if any of the components is null
	}
	
	
	private byte[] encryptSalt(byte[] salt) {
		
		byte[] encryptedSalt = null;
		try {
			SecretKeySpec saltEncryptionKeySpec = new SecretKeySpec(SecuredPasswordSettings.saltEncryptionKeyBytes(), "AES");
			Cipher saltCipher = Cipher.getInstance(SecuredPasswordSettings.saltEncryptionCipher);
			saltCipher.init(Cipher.ENCRYPT_MODE, saltEncryptionKeySpec);
			encryptedSalt = saltCipher.doFinal(salt);
			
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (NoSuchAlgorithmException |
				 NoSuchPaddingException |
				 InvalidKeyException |
				 IllegalBlockSizeException |
				 BadPaddingException e) {    
			log.severe("JRR-Security (Unsupported configuration): Exception while encrypting password salt: " + e.getMessage());
		}

		return encryptedSalt;    // returns null if any exceptions are raised during encryption
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
			log.severe("JRR-Security: Exception while deriving key from password: " + e.getMessage());
		}   
		
		return dk;
	}

}
