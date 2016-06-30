package com.sp.saml;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.sp.cert.Cert509Reader;

public class SamlTest {

	private final static Logger logger = LoggerFactory.getLogger(SamlTest.class);

	public static void main(String args[]) throws Exception {
		PrivateKeyEntry privateKeyEntry = TestUtils.readPrivateKeyEntryFromKeystore();
		PrivateKey pk = privateKeyEntry.getPrivateKey();
		X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();

		/*
		 * Initializes the OpenSAML library, loading default configurations.
		 */
		DefaultBootstrap.bootstrap();
		SamlObjectBuilder builder = new SamlObjectBuilder(Configuration.getBuilderFactory());

		/*
		 * create signature
		 */
		Signature signature = builder.buildSignature();

		BasicX509Credential signingCredential = new BasicX509Credential();
		signingCredential.setEntityCertificate(certificate);
		signingCredential.setPrivateKey(pk);
		signature.setSigningCredential(signingCredential);

		// This is also the default if a null SecurityConfiguration is specified
		SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();

		SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);

		/*
		 * create assertion
		 */
		Assertion assertion = builder.buildAssertion();
		Issuer newIssuer = builder.buildIssuer();
		newIssuer.setNameQualifier("my.xxx:email");
		newIssuer.setValue("some.de");
		assertion.setIssuer(newIssuer);

		Subject newSubject = builder.buildSubject();
		NameID newNameID = builder.buildNameId();
		newNameID.setValue("sombody@some.de");
		newSubject.setNameID(newNameID);
		assertion.setSubject(newSubject);

		/*
		 * create response
		 */
		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) SAMLWriter.getSAMLBuilder()
		    .getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlResponse = responseBuilder.buildObject();
		samlResponse.getAssertions().add(assertion);
		samlResponse.setSignature(signature);

		// marshall before signing is required!!
		Element beforeSignedElement = new ResponseMarshaller().marshall(samlResponse);
		logger.info("\n\n*******************************\n" + XMLHelper.nodeToString(beforeSignedElement));

		Signer.signObject(signature);
		Element signedElement = new ResponseMarshaller().marshall(samlResponse);
		logger.info("\n\n*******************************\n" + XMLHelper.nodeToString(signedElement));

		/*
		 * Verifying signatures with OpenSAML
		 */
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(samlResponse.getSignature());
		Credential cred = getPublicKeyCredentilas();
		SignatureValidator sigValidator = new SignatureValidator(cred);
		sigValidator.validate(samlResponse.getSignature());

	}

	private static Credential getPublicKeyCredentilas() throws Exception {
		BasicX509Credential cred = new BasicX509Credential();
		X509Certificate x509Certificate = Cert509Reader.readFromKey(new File("./saml-key.cer"));
		cred.setPublicKey(x509Certificate.getPublicKey());
		return cred;
	}

}
