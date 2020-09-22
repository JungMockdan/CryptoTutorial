package com.crypto.howto;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class CryptoRsa {
// 여기서 바로 수정하면.
	private static String RSA_INS_STR = "RSA";
	 public static void main(String[] args) throws IOException{
		 String plainText ="this is RSA 123aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		 System.out.println("평문 ::::::"+plainText);
         KeyPair keyPair;
         try {
        	 System.out.println("\n모드 : RSA-1024 ");
        	 keyPair = createKeypair(1024);
        	 byte[] cipherBytes1024 = encryptRSA_INS_STR(keyPair.getPublic(),plainText.getBytes("UTF-8"));
 			 System.out.println("암호문 :: 1024- "+new String(cipherBytes1024));
 			 byte[] decryptBytes1024 = decryptRSA_INS_STR(keyPair.getPrivate(),  cipherBytes1024);
 			 System.out.println("복호문 :: 1024- "+new String(decryptBytes1024));

 			 System.out.println("\n모드 : RSA-2048 ");
        	 keyPair = createKeypair(2048);
        	 byte[] cipherBytes2048 = encryptRSA_INS_STR(keyPair.getPublic(),plainText.getBytes("UTF-8"));
        	 System.out.println("암호문 :: 1024- "+new String(cipherBytes2048));
        	 byte[] decryptBytes2048 = decryptRSA_INS_STR(keyPair.getPrivate(),  cipherBytes2048);
        	 System.out.println("복호문 :: 1024- "+new String(decryptBytes2048));
		} catch (Exception e) {
			e.printStackTrace();
		}
	 }


	private static byte[] decryptRSA_INS_STR(PrivateKey privateKey, byte[] cipherBytes) {
		return decryptRSA(privateKey, cipherBytes);
	}

	private static byte[] encryptRSA_INS_STR(PublicKey publicKey, byte[] plainTextBytes) {
		return encryptRSA(publicKey, plainTextBytes);
	}


	private static byte[] encryptRSA(PublicKey publicKey, byte[] plainTextBytes) {
		Cipher cipher = null;
		byte[] encrypted = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			encrypted = cipher.doFinal(plainTextBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	}
	private static byte[] decryptRSA(PrivateKey privateKey, byte[] cipherBytes) {
		Cipher cipher = null;
		byte[] decrypted = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decrypted = cipher.doFinal(cipherBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypted;
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
