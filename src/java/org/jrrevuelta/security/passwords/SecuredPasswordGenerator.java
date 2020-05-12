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


/**
 * The secured password generator processes a given password to be stored in the system so that
 * it can be used in the future to verify incoming claimed passwords. It prepares a 
 * <code>SecuredPassword</code> object according to the specification [JRRevuelta-2019].<br>
 * <br>
 * The generated object can then be stored in the system with the assurance that it is not reversable
 * and that it is protected against attacks. Normally a <code>String</code> representation would be
 * appropriate to keep in storage, although a raw form could also be appropriate.<br>
 * <br> 
 * [JRRevuelta-2019]: José Ramón Revuelta, Abril/2019, Recomendación, Almacenamiento seguro de contraseñas de usuarios.<br>
 * <br>
 * @author JRRevuelta
 */
public class SecuredPasswordGenerator {
	
	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");
	
	
	public SecuredPasswordGenerator() {
		super();
		log.finest("JRR-Security: SecuredPasswordGenerator object instantiated.");
	}

	
	/**
	 * This method is the only one needed to generate the <code>SecuredPassword</code> object that is needed
	 * to safely store a password in the system. It takes the original password as entered by the user
	 * and makes all the necessary transformations according to the specification to produce the secured
	 * representation of it which can be later used for verification.<br>
	 * <br>
	 * @param originalPassword A <code>String</code> containing the clear text password entered by
	 * the user in the system in order to be processed for safe-keeping.
	 * @return A <code>SecuredPassword</code> object with the components that represent the
	 * original password in such a way (as described in the specification) that it is protected for
	 * possible attacks.
	 */
	public SecuredPassword generateNewSecuredPassword(String originalPassword) {

		byte[] derivedKey = null;
		byte[] salt = null;
		int counter = 0;
		SecureRandom random = new SecureRandom();
		
		// Validate input
		if (originalPassword == null || originalPassword.isEmpty()) {
			return null;
		}
		
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
			
		// None of these exceptions should be raised (based on input, only by unsupported configuration)
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			log.severe("JRR-Security (Unsupported configuration): Exception while deriving key from password: " + e.getMessage());
		}   
		
		return dk;
	}

}
