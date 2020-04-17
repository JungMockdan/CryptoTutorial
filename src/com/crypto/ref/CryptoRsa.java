package com.crypto.ref;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class CryptoRsa {

	 public static void main(String[] args) throws IOException{
		 String plainText ="평aaaaaaaaa문";
		 System.out.println("평문 ::::::"+plainText);
         KeyPair keyPair;
         try {
        	 System.out.println("\n모드 : RSA-1024 ");
        	 keyPair = createKeypair(1024);
        	 decrypt(keyPair.getPrivate(), encrypt(keyPair.getPublic(),plainText));

        	 System.out.println("\n모드 : RSA-2048 ");
        	 keyPair = createKeypair(2048);
        	 decrypt(keyPair.getPrivate(), encrypt(keyPair.getPublic(),plainText));
		} catch (Exception e) {
			e.printStackTrace();
		}
	 }


	private static String encrypt(PublicKey publicKey,  String plainText) {
		String cTxt = "";
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
			cTxt += new String(DatatypeConverter.printBase64Binary(encrypted));
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("암호화: "+cTxt);
		return cTxt;
	}
	
	private static String decrypt(PrivateKey privateKey, String cTxt) {
		String dTxt = "";
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decrypted = DatatypeConverter.parseBase64Binary(cTxt);
			dTxt = new String(cipher.doFinal(decrypted), "utf-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("복호화: "+dTxt);
		return dTxt;
		
	}

	private static KeyPair createKeypair(int bits) {
		SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator;
        KeyPair keyPair=null;
        try {
        	keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        	keyPairGenerator.initialize(bits, secureRandom);
        	keyPair = keyPairGenerator.genKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
        return keyPair;
	}
}
