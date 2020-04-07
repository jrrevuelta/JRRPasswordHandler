package org.jrrevuelta.security.passwords;

import java.util.logging.Logger;

import org.apache.catalina.CredentialHandler;

/**
 * Implementation of Tomcat's Credential Handler according to specifications from [JRRevuelta-2019].<br>
 * <br>
 * This component allows a Tomcat installation to store and validate passwords that are processed and
 * stored according to the specification.<br>
 * <br>
 * Applications need to process their user's passwords according to the document, by using the tools in
 * this implementation and storing the resulting password objects in the users' database (as managed by
 * your Tomcat installation). When a login is attempted using Tomcat's means (ie. FORM validation in a webapp)
 * the appropriate validation will be done by Tomcat.<br>
 * <br>
 * Configuration of Tomcat's Realm component needs a nested CredentialHandler component with this class as
 * the implementation (ie. <code>&lt.CredentialHandler class="org.jrrevuelta.security.passwords.JrrCredentialHandler"/&gt.</code> )
 * no further parameters are needed.<br>
 * <br>
 * [JRRevuelta-2019]: José Ramón Revuelta, Abril/2019, Recomendación, Almacenamiento seguro de contraseñas de usuarios.<br>
 * <br>
 * @author JRRevuelta
 */
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
