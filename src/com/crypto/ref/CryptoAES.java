package com.crypto.ref;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class CryptoAES {

	
	private static int KEY_SIZE=0;//key size�� ���� ���� ���� �޶�����.


	
	public CryptoAES() {
		// �ʱ�ȭ ����.
	}
	
	public static void main(String[] args) throws IOException  {
		System.out.println("����!!");
		BufferedReader keyreader = new BufferedReader(new FileReader("128"));
		String key = keyreader.readLine();
		System.out.println("key:::"+key);
	}

	/**
	 * ��ȣȭ
	 * @param crpt_mode 
	 * @param crpt_bits 
	 * @param crpt 
	 * @param pt 
	 * @return
	 */
	public String encription(String pt, String crpt, String crpt_bits, String crpt_mode) {
		String key = "keey";
		
		int round = key.length()+6;//AES128
		CriptHelp h = new CriptHelp();
		for(int i=0 ; i<round ; i++) {
			this.encRound(i,h, key);
		}
		
		
		
		return null;
		
	}
	
	private void encRound(int round, CriptHelp h, String key) {
		String state="";
		state = h.funcSubBytes();//��ġ
		state = h.funcShiftRows();//ġȯ
		state = h.funcMixColumns(round);//����
		state = h.funcAddRoundKey();	
		
	}
	private void decRound(int round, CriptHelp h, String key) {
		h.funcSubBytes();
		h.funcShiftRows();
		h.funcMixColumns(round);
		h.funcAddRoundKey();		
	}

	/**
	 * ��ȣȭ
	 * @return
	 */
	private String decription() {
		return null;
		
	}
	
}
