package com.crypto.ref;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class CriptHelp {
	/**
	 * AES ���� ����Լ�
	 * ����Ʈ ����
	 * @return
	 */
	public String funcSubBytes() {
		
		return null;
		
	}
	
	/**
	 * AES ���� ����Լ�
	 * ��ȯ����� �̿��� ����Ʈ ��ü ��ȯ
	 * @return
	 */
	public String funcShiftRows() {
		return null;
		
	}
	/**
	 * AES ���� ����Լ�
	 * �������
	 * @param round 
	 * @return
	 */
	public static String funcMixColumns(int round) {
		return null;
		
	}
	
	/**
	 * AES ���� ����Լ�
	 * @param �ش��� XOR ���Ʈ Ű
	 * ��Ʈ���� : XOR
	 * @return
	 */
	public static String funcAddRoundKey() {
		return null;
		
	}
	
	/**
	 * �ʱ��Ʈ����
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
	 * Ű����
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
