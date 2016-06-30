package com.sp.cert;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Cert509Reader {

	public static X509Certificate readFromKey(File cerFile) throws FileNotFoundException, CertificateException {
		FileInputStream fis = new FileInputStream(cerFile);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bufin);
		return certificate;
	}

	/**
	 * 
	 * @param keystoreFile
	 * @param password
	 *          same keystore an certificate
	 * @param certificateAliasName
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public static X509Certificate readFromKeystore(File keystoreFile, String password, String certificateAliasName)
	    throws CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException,
	    IOException {
		PrivateKeyEntry privateKeyEntry = readPrivateKeyFromKeystore(keystoreFile, password, certificateAliasName);
		return (X509Certificate) privateKeyEntry.getCertificate();
	}

	public static PrivateKeyEntry readPrivateKeyFromKeystore(File keystoreFile, String password,
	    String certificateAliasName) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
	    IOException, UnrecoverableEntryException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream fis = new FileInputStream(keystoreFile);
		ks.load(fis, password.toCharArray());

		PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(certificateAliasName,
		    new KeyStore.PasswordProtection(password.toCharArray()));
		return pkEntry;
	}

	/**
	 * reads a public key from a file
	 * 
	 * @param filename
	 *          name of the file to read
	 * @param algorithm
	 *          is usually RSA
	 * @return the read public key
	 * @throws Exception
	 */
	public static PublicKey getPemPublicKey(String filename, String algorithm) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		String temp = new String(keyBytes);
		String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\r\n", "");
		publicKeyPEM = publicKeyPEM.replace("\r\n-----END PUBLIC KEY-----", "");

		Base64 b64 = new Base64();
		byte[] decoded = b64.decode(publicKeyPEM);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePublic(spec);
	}

}
