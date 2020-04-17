package com.crypto.ref;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class CriptHelp {
	/**
	 * AES 라운드 사용함수
	 * 바이트 대입
	 * @return
	 */
	public String funcSubBytes() {
		
		return null;
		
	}
	
	/**
	 * AES 라운드 사용함수
	 * 순환행렬을 이용한 바이트 대체 변환
	 * @return
	 */
	public String funcShiftRows() {
		return null;
		
	}
	/**
	 * AES 라운드 사용함수
	 * 산술연산
	 * @param round 
	 * @return
	 */
	public static String funcMixColumns(int round) {
		return null;
		
	}
	
	/**
	 * AES 라운드 사용함수
	 * @param 해당블록 XOR 라운트 키
	 * 비트연산 : XOR
	 * @return
	 */
	public static String funcAddRoundKey() {
		return null;
		
	}
	
	/**
	 * 초기비트생성
	 * @return
	 */
	public static String getIV() {
		//Cipher
		
//		KeyGenerator kgen = KeyGenerator.getInstance("AES");
//	    kgen.init(128, sr);
//	    
//	    SecretKey skey = kgen.generateKey();
		return null;
		
	}

	/**
	 * 키생성
	 * @param keySize
	 * @return
	 */
	public static KeyPairGenerator keygen(String instance) {
		KeyPairGenerator keyGen=null;
		try {
			keyGen = KeyPairGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyGen;
		
	}
}
