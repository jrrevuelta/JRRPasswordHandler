package org.jrrevuelta.security.passwords;

import java.math.BigInteger;


/**
 * This static class contains the parameters to deal with the algorithms described in the specification
 * [JRRevuelta-2019], according to the recommended values and sizes.<br>
 * <br>
 * The implementation of the algorithms in this package reference these values, so this is the central point
 * to reconfigure the code (to a certain extent).<br>
 * <br>
 * [JRRevuelta-2019]: José Ramón Revuelta, Abril/2019, Recomendación, Almacenamiento seguro de contraseñas de usuarios.<br>
 * <br>
 * @author JRRevuelta
 */
public class SecuredPasswordSettings {
	
	// Parameters for the execution of the algorithm as described in [JRRevuelta2019].
	static final String prf = "HmacSHA512";
	static final int hlen = 512;

	static final int derivedKeySizeBytes = hlen / 8;
	static final int saltSizeBytes = hlen / 8;
	static final int countLimit = 1000;
	
	static final String saltEncryptionCipher = "AES/ECB/NoPadding";
	
	static final String passwordEncoding = "UTF-8";
	
	// Hex AES-256 key to be used ONLY within the package to encrypt/decrypt the salt   TODO: Protect the key using a HSM
	static final String saltEncryptionKey = "35EA81CCEFF120A7CD2F4513A8976DC5DC32090A558CC50361DB71555A683B85";   // SAMPLE KEY (DO NOT USE)
	static byte[] saltEncryptionKeyBytes() { return new BigInteger(saltEncryptionKey, 16).toByteArray(); }

}
