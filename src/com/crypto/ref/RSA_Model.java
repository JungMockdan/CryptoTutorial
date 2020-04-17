package com.crypto.ref;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class RSA_Model {

	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	
	public RSA_Model() {
		super();
	}
	

    public RSA_Model(int bits) {
    	KeyPair keys;
    	try {
    		keys =genRSAKeyPair(bits);
    		this.setPublicKey(keys.getPublic());
    		this.setPrivateKey(keys.getPrivate());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}




	/**
     * 비트별 RSA 키쌍을 생성합니다.
     * @param bits
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair genRSAKeyPair(int bits) throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();

        KeyPairGenerator gen;

        gen = KeyPairGenerator.getInstance("RSA");

        gen.initialize(bits, secureRandom);

        KeyPair keyPair = gen.genKeyPair();

        return keyPair;

    }

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

    

	
}
