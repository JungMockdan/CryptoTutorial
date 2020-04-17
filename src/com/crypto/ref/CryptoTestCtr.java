package com.crypto.ref;

import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CryptoTestCtr {

	
	public static String encrypt(String key, String initVector, String value) {
	       try {
	         IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
	         SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

	         Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
	         cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

	         byte[] encrypted = cipher.doFinal(value.getBytes());
	         String rs = DatatypeConverter.printHexBinary(encrypted);
	         System.out.println("¾ÏÈ£È­::"+rs);
	         return rs;
	       }
	       catch (Exception ex) {
	         throw new RuntimeException(ex);
	       }
	     }

	     public static String decrypt(String key, String initVector, String encrypted) {
	       try {
	         IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
	         SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

	         Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
	         cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

	         byte[] decrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(encrypted));
	         return new String(decrypted);
	       }
	       catch (Exception ex) {
	         ex.printStackTrace();
	       }

	       return null;
	     }

	     public static void main(String[] args) {
	       String key = "Bar12345Bar12345"; // 128 bit key
	       String initVector = "RandomInitVector"; // 16 bytes IV

	       System.out.println(
	    		   decrypt(key, initVector,
	    				   encrypt(key, initVector, "Hello World")));
//	       for (int i = 0; i < 1000; ++i) {
//	         String encrypted = encrypt(key, initVector, StringUtils.leftPad("" + i, 3, '0'));
//	         int encLen = encrypted.length();
//	         System.out.println("i = " + i + ": enc='" + encrypted + "', dec='" + decrypted + "', length=" + encLen);
//	       }
	     }
	
	
	
}
