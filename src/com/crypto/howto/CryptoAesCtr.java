package com.crypto.howto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CryptoAesCtr {

	private static String AES_CTR_INS_STR = "AES/CTR/PKCS5PADDING";
	public static void main(String args[]) throws IOException 
    {
		String plainText ="this is aes ctr 123aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
//		String plainText ="this is jmd123";
		System.out.println("평문 ::::::"+plainText+", "+ plainText.getBytes().length +"byte");
		SecretKey secretKey;
		IvParameterSpec ivSpec; 
		try {
			
			secretKey = (SecretKey) createAesKey("this is cipherKey".getBytes("UTF-8"), 256);
//			secretKey = (SecretKey) createAesKey(256);
			
//			IvParameterSpec ivSpec = getIV(secretKey);//
//			IvParameterSpec ivSpec = getIV();
			ivSpec = getIV("initiol vector creation");
			byte[] cipherBytes256 = encryptAES_CTR_INS_STR(secretKey,  plainText.getBytes("UTF-8"), ivSpec);
			System.out.println("암호문 :: 256- "+new String(cipherBytes256+", "+ cipherBytes256.length +"byte"));
			byte[] decryptBytes256 = decryptAES_CTR_INS_STR(secretKey,  cipherBytes256, ivSpec);
			System.out.println("복호문 :: 256- "+new String(decryptBytes256)+", "+ decryptBytes256.length +"byte");
			
			secretKey = (SecretKey) createAesKey(128);
			ivSpec = getIV("initiol vector creation");
			byte[] cipherBytes128 = encryptAES_CTR_INS_STR(secretKey,  plainText.getBytes("UTF-8"), ivSpec);
			System.out.println("암호문 :: 128- "+new String(cipherBytes128)+", "+ cipherBytes128.length +"byte");
			byte[] decryptBytes128 = decryptAES_CTR_INS_STR(secretKey,  cipherBytes128, ivSpec);
			System.out.println("복호문 :: 128- "+new String(decryptBytes128));

			secretKey = (SecretKey) createAesKey(192);
			ivSpec = getIV("initiol vector creation");
			byte[] cipherBytes192 = encryptAES_CTR_INS_STR(secretKey,  plainText.getBytes("UTF-8"), ivSpec);
			System.out.println("암호문 :: 192- "+new String(cipherBytes192));
			byte[] decryptBytes192 = decryptAES_CTR_INS_STR(secretKey,  cipherBytes192, ivSpec);
			System.out.println("복호문 :: 192- "+new String(decryptBytes192));
		} catch (Throwable e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	
	private static IvParameterSpec getIV() {
		byte[] ivBytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		return new IvParameterSpec(ivBytes);
	}

	/**
	 * 16bytes  iv
	 * @param secretKey
	 * @return IvParameterSpec
	 * @throws UnsupportedEncodingException 
	 */
	private static IvParameterSpec getIV(SecretKey secretKey) throws UnsupportedEncodingException {

		byte[] secretKeyBytes = secretKey.getEncoded();
		System.out.println("secretKeyBytes.length::: "+secretKeyBytes.length);
		byte[] ivBytes = new byte[16];
		for(int i=0;i<16;i++) {
			ivBytes[i] = secretKeyBytes[i];
		}
		System.out.println("ivBytes.length::: "+ivBytes.length);

		return new IvParameterSpec(ivBytes);
	}
	private static IvParameterSpec getIV(String ivStr) throws UnsupportedEncodingException {
		
		if(ivStr.length()<16) ivStr += "1234567890123456";
		byte[] secretKeyBytes = ivStr.getBytes();
		byte[] ivBytes = new byte[16];
		for(int i=0;i<16;i++) {
			ivBytes[i] = secretKeyBytes[i];
		}
		System.out.println("ivBytes.length::: "+ivBytes.length);
		return new IvParameterSpec(ivBytes);
	}

	private static Key createAesKey(byte[] keyBytes, int keysize) {
		// check keyBytes length
		byte[] aesKeyBytes = new byte[keysize/8];
		SecretKeySpec keySpec = null;
		// Generate SecretKey
		switch (keyBytes.length) {
		case 128:
		case 192:
		case 256:
//			System.arraycopy(keyBytes, 0, aesKeyBytes, 0, aesKeyBytes.length);
			keySpec = new SecretKeySpec(keyBytes, "AES");
			break;

		default:
			keyBytes = forcedPadding(keyBytes,keysize);
//			System.arraycopy(keyBytes, 0, aesKeyBytes, 0, aesKeyBytes.length);
			keySpec = new SecretKeySpec(keyBytes, "AES");
			break;
		}
		
		return keySpec;
	}
	


	private static Key createAesKey(int keysize) throws Throwable {
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(keysize);
//		System.out.println(keyGenerator.generateKey().getAlgorithm());
//		System.out.println(keyGenerator.generateKey().getEncoded().length);
		return keyGenerator.generateKey();
	}
	
	private static byte[] decryptAES_CTR_INS_STR(Key key,  byte[] cipherBytes, IvParameterSpec ivSpec) throws Exception {
		return decryptAES(AES_CTR_INS_STR, key, cipherBytes, ivSpec);
	}
	private static byte[] encryptAES_CTR_INS_STR(Key key,  byte[] plainBytes, IvParameterSpec ivSpec) throws Exception {
		return encryptAES(AES_CTR_INS_STR, key, plainBytes, ivSpec);
	}
	
	private static byte[] encryptAES(String instanceType, Key key, byte[] plainBytes, IvParameterSpec ivSpec) throws Exception {
		
		Cipher cipher = Cipher.getInstance(instanceType);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		return cipher.doFinal(plainBytes);
	}
	
	private static byte[] decryptAES(String instanceType, Key key,  byte[] cipherByte, IvParameterSpec ivSpec) throws Exception {
		
		Cipher cipher = Cipher.getInstance(instanceType);
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		return cipher.doFinal(cipherByte);
	}

	/**
	 * 키의 비트수를 맞춰주는 함수. 암호화bit에 따라 패딩한다.
	 * @param keyBytes : 주어진 키
	 * @param keysize : 암호화비트-> 바이트로 한 int
	 * @return
	 */
	private static byte[] forcedPadding(byte[] keyBytes, int keysize) {
		
		int padCnt = keysize - keyBytes.length;
		byte[] newKeyBytes = new byte[keysize/8];
		for(int i = 0 ; i < newKeyBytes.length ; i++) {
			byte b ;
			if(padCnt>0 && i>=keyBytes.length) {
				b = 0;
			}else {
				b = keyBytes[i];
			}
			newKeyBytes[i] = b;
		}
		System.out.println("패딩된결과 ::"+new String(newKeyBytes));
		return newKeyBytes;
	}
	
	
	
}
