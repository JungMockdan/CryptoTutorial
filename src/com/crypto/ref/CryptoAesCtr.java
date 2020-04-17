package com.crypto.ref;

import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CryptoAesCtr {

	private static String AES_CTR_INS_STR = "AES/CTR/PKCS5PADDING";
	public static void main(String args[]) throws IOException 
    {
		String plainText ="hello world";
		String key = ""; // 128 bit key
	    String initVector = "1234567890123456"; // 16 bytes IV
	    System.out.println("평문 ::::::"+plainText);
	    
	    //AES/CTR
	    key = "keeeey1234567890"; // 128 bit key
		decrypt(key, initVector ,encrypt(key, initVector, plainText, 128), 128);
		decrypt(key, initVector ,encrypt(key, initVector, plainText, 192), 192);
		decrypt(key, initVector ,encrypt(key, initVector, plainText, 256), 256);

    }


	private static String encrypt(String key, String initVector, String plainText, int bits) {
		
		String cTxt = "";
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
	        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

	        Cipher cipher = Cipher.getInstance(AES_CTR_INS_STR);
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

	        byte[] encrypted = cipher.doFinal(plainText.getBytes());
	        String rs = DatatypeConverter.printBase64Binary(encrypted);
			cTxt = new String(DatatypeConverter.printBase64Binary(encrypted));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("\n모드 : "+AES_CTR_INS_STR+"-"+bits+", 암호화: "+cTxt);
		return cTxt;
	}
	
	private static String decrypt(String key, String initVector, String cTxt, int bits) {
		String dTxt = "";
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
	         SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

	         Cipher cipher = Cipher.getInstance(AES_CTR_INS_STR);
	         cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

             byte[] decrypted = DatatypeConverter.parseBase64Binary(cTxt); 
             dTxt = new String(cipher.doFinal(decrypted));
            
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("모드 : "+AES_CTR_INS_STR+"-"+bits+", 복호화: "+dTxt);
		return dTxt;
	}
	
	
	
}
