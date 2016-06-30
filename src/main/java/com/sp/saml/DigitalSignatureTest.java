package com.sp.saml;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.apache.commons.codec.binary.Base64;

public class DigitalSignatureTest {

	public static void main(String[] args) throws Exception {

		/*
		 * get the private and public key from somewhere
		 */
		PrivateKeyEntry privateKeyEntry = TestUtils.readPrivateKeyEntryFromKeystore();
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

		/*
		 * create signature
		 */
		byte[] data = "test".getBytes("UTF8");
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initSign(privateKey);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		byte[] encodedSignature = new Base64().encode(signatureBytes);
		System.out.println("Singature:" + encodedSignature);

		/*
		 * verify signature
		 */
		sig = Signature.getInstance("MD5WithRSA");
		sig.initVerify(publicKey);
		sig.update(data);
		byte[] signatureDecodedBack = new Base64().decode(encodedSignature);
		System.out.println("Verfiy:" + sig.verify(signatureDecodedBack));
	}

}
