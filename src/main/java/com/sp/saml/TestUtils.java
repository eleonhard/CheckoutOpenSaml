package com.sp.saml;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import com.sp.cert.Cert509Reader;

public class TestUtils {

	static PrivateKeyEntry readPrivateKeyEntryFromKeystore() throws KeyStoreException, NoSuchAlgorithmException,
	    CertificateException, IOException, UnrecoverableEntryException {
		PrivateKeyEntry privateKeyEntry = Cert509Reader.readPrivateKeyFromKeystore(new File("./saml-keystore"), "store12",
		    "saml");
		return privateKeyEntry;
	}

}
