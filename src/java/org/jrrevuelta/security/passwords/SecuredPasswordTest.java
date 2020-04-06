package org.jrrevuelta.security.passwords;

import org.apache.catalina.CredentialHandler;

public class SecuredPasswordTest {

	public static void main(String[] args) throws Exception {

		// Use a Credential Handler compatible with Tomcat's
		CredentialHandler handler = new JrrCredentialHandler();
		System.out.println("\n\tUsing Tomcat's Credential Handler: \n");
		
		String pass1 = "Good";
		String pass2 = "Wrong";
		String pass3 = "not good";
		
		// Generate the secure version of the password to keep in the DB
		String storedPassword = handler.mutate(pass1);
		
		// This is what is kept in the DB
		System.out.println("Stored Password: " + storedPassword + "\n");
				
		// Verify claimed passwords against the stored one
		System.out.println(pass1 + ": " + handler.matches(pass1, storedPassword));  // This is the ONLY correct password
		System.out.println(pass2 + ": " + handler.matches(pass2, storedPassword));
		System.out.println(pass3 + ": " + handler.matches(pass3, storedPassword));
		
		
		// Use SecuredPassword objects directly
		System.out.println("\n\n\tUsing SecuredPassword objects: \n");
		
		SecuredPasswordGenerator gen = new SecuredPasswordGenerator();
		SecuredPassword securedPassword = gen.generateNewSecuredPassword(pass1);
		
		SecuredPasswordVerifier ver = new SecuredPasswordVerifier(securedPassword);
		System.out.println(pass1 + ": " + ver.verifyPassword(pass1));  // This is the ONLY correct password
		System.out.println(pass2 + ": " + ver.verifyPassword(pass2));
		System.out.println(pass3 + ": " + ver.verifyPassword(pass3));
		
		
/*		
		System.out.println();
		System.out.println("B033B042D470600A18EFA56FEA3FDA99");
		BigInteger o = new BigInteger("B033B042D470600A18EFA56FEA3FDA99",16);
		byte[] b = o.toByteArray();
		if (b.length > 16) {
			byte[] b2 = new byte[16];
			for (int i=0; i<16; i++) {
				b2[i] = b[i+1];
			}
			b = b2;
		}
		System.out.println("size of b: " + b.length);
		for (int i=0; i<b.length; i++) {
			System.out.println("Byte[" + i + "]: " + b[i]);
		}
		BigInteger u = new BigInteger(1, b);
		String s = u.toString(16).toUpperCase();
		System.out.println(s);

*/
	}

}
