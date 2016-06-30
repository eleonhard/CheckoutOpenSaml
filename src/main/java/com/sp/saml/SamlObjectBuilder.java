package com.sp.saml;

import javax.xml.namespace.QName;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.Signature;

public class SamlObjectBuilder {

	private XMLObjectBuilderFactory builderFactory;

	public SamlObjectBuilder(XMLObjectBuilderFactory builderFactory) {
		this.builderFactory = builderFactory;
	}

	public Signature buildSignature() {
		return (Signature) build(Signature.DEFAULT_ELEMENT_NAME);
	}

	public Assertion buildAssertion() {
		return (Assertion) build(Assertion.DEFAULT_ELEMENT_NAME);
	}

	public Issuer buildIssuer() {
		return (Issuer) build(Issuer.DEFAULT_ELEMENT_NAME);
	}

	private XMLObject build(QName defaultElementName) {
		return builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
	}

	public Subject buildSubject() {
		return (Subject) build(Subject.DEFAULT_ELEMENT_NAME);
	}

	public NameID buildNameId() {
		return (NameID) build(NameID.DEFAULT_ELEMENT_NAME);
	}

}
