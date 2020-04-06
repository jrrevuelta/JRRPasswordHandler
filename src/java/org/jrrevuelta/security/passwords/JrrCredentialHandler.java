package org.jrrevuelta.security.passwords;


import java.util.logging.Logger;

import org.apache.catalina.CredentialHandler;

public class JrrCredentialHandler implements CredentialHandler {
	
	private static Logger log = Logger.getLogger("org.jrrevuelta.security.passwords");

	
	@Override
	public boolean matches(String password, String securedPassword) {
		log.finest("JRR-SecurePassword: Matching password.");
		
		// Generate a verifier based on the stored secured password
		SecuredPasswordVerifier ver = new SecuredPasswordVerifier(new SecuredPassword(securedPassword));
		
		return ver.verifyPassword(password);
	}

	@Override
	public String mutate(String password) {
		log.finest("JRR-SecurePassword: Generating password.");
		
		// Generate the secure version of the password to keep in store
		SecuredPasswordGenerator gen = new SecuredPasswordGenerator();
		SecuredPassword securedPassword = gen.generateNewSecuredPassword(password);
		
		return securedPassword.toString();
	}
}
