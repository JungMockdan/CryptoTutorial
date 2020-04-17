package com.crypto.ref;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_Model {

	private String iv;
	private Key keySpec;
	
	private SecretKey scrtKey;
	private IvParameterSpec ivSpec;

	
	public AES_Model() {
		super();
		// TODO Auto-generated constructor stub
	}


	/**
	 * @param key
	 * @param crptType
	 */
	public AES_Model(String key, String crptType) {
//		System.out.println("### 클래스 생성자호출");
		try {
			byte[] keyBytes = new byte[16];
			byte[] b = key.getBytes("UTF-8");
			System.arraycopy(b, 0, keyBytes, 0, keyBytes.length);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, crptType);
			this.setIv(key.substring(0, 16));
			this.setKeySpec(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public AES_Model(String key, String crptType, int blockSize) {
		System.out.println("\n### 클래스 생성자::blockSize::"+blockSize);
		try {
			SecureRandom rng = new SecureRandom();
			IvParameterSpec ivForCBC = createIV(blockSize, rng);
			
			Provider provider = null;
		    SecretKey secretKey = createSecretKey(crptType, 128, provider, rng);
		        
			byte[] keyBytes = new byte[16];
			byte[] b = key.getBytes("UTF-8");
			System.arraycopy(b, 0, keyBytes, 0, keyBytes.length);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, crptType);
			
			this.setIvSpec(ivForCBC);
			this.setIv(key.substring(0, 16));
			this.setKeySpec(keySpec);
			this.setScrtKey(secretKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	private SecretKey createSecretKey(String algorithm, int keysize, Provider provider, SecureRandom rng) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator;
        if (provider!=null) {
            keyGenerator = KeyGenerator.getInstance(algorithm, provider);
        } else {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        }

        if (rng!=null) {
            keyGenerator.init(keysize, rng);
        } else {
            // not really needed for the Sun provider which handles null OK
            keyGenerator.init(keysize);
        }

        return keyGenerator.generateKey();
	}


	private IvParameterSpec createIV(int blockSize, SecureRandom rng) {
		byte[] iv = new byte[blockSize];
		SecureRandom theRNG = rng==null?new SecureRandom():rng;
		theRNG.nextBytes(iv);
        return new IvParameterSpec(iv);
	}
	public static IvParameterSpec readIV(int ivSizeBytes, InputStream is) throws IOException {
        byte[] iv = new byte[ivSizeBytes];
        int offset = 0;
        while (offset < ivSizeBytes) {
            int read = is.read(iv, offset, ivSizeBytes - offset);
            if (read == -1) {
                throw new IOException("Too few bytes for IV in input stream");
            }
            offset += read;
        }
        return new IvParameterSpec(iv);
    }


	public String getIv() {
		return iv;
	}


	public void setIv(String iv) {
		this.iv = iv;
	}


	public Key getKeySpec() {
		return keySpec;
	}


	public void setKeySpec(Key keySpec) {
		this.keySpec = keySpec;
	}


	public IvParameterSpec getIvSpec() {
		return ivSpec;
	}


	public void setIvSpec(IvParameterSpec ivSpec) {
		this.ivSpec = ivSpec;
	}
	
	public SecretKey getScrtKey() {
		return scrtKey;
	}


	public void setScrtKey(SecretKey scrtKey) {
		this.scrtKey = scrtKey;
	}


	@Override
	public String toString() {
		return "AES_Model [iv=" +iv + ", keySpec=" + keySpec.toString() + ", scrtKey=" + scrtKey.toString() + ", ivSpec=" + ivSpec.toString() + "]";
	}
	
	
	
	
	
}
