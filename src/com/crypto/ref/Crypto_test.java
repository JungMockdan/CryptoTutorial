package com.crypto.ref;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class Crypto_test {

//	private static String iv;
//	private static Key keySpec;
//
//	public CryptoAES_test(String key, String crptType) {
//		System.out.println("\n### Ŭ���� ������");
//		try {
//			byte[] keyBytes = new byte[16];
//			byte[] b = key.getBytes("UTF-8");
//			System.arraycopy(b, 0, keyBytes, 0, keyBytes.length);
//			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, crptType);
//			this.iv = key.substring(0, 16);
//			this.keySpec = keySpec;
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
	
	public static void main(String args[]) throws IOException 
    {
		System.out.println("�������������������������������������������");
		
		Map<String,String> valid = getValidity(args);
		String isValid = valid.get("isValid");
		String errArgs = valid.get("errArgs");
		if(isValid.equals("Y")) {
			String gbn = args[0];// e : ��ȣȭ, d:  ��ȣȭ
			
			if(gbn.equals("e")) {
				String cTxt = "";
				String dTxt = "";
				if( args[2].toLowerCase().equals("aes")) {
					//��ȣȭ
//					cTxt = encryptAES(args[1],args[2],args[3],args.length>4?args[4]:null);
					//��ȣȭ
//					dTxt = decryptAES(cTxt,args[2],args[3],args.length>4?args[4]:null);
					//��|��ȣȭ
					cTxt = cryptAES( "e", args[1],args[2],args[3],args.length>4?args[4]:null);
					dTxt = cryptAES( "d", cTxt,args[2],args[3],args.length>4?args[4]:null);
					cTxt = cryptAES( "e", args[1],args[2],"192",args.length>4?args[4]:null);
					dTxt = cryptAES( "d", cTxt,args[2],"192",args.length>4?args[4]:null);
					cTxt = cryptAES( "e", args[1],args[2],"256",args.length>4?args[4]:null);
					dTxt = cryptAES( "d", cTxt,args[2],"256",args.length>4?args[4]:null);
				}

				if( args[2].toLowerCase().equals("rsa")) {
					
//					RSA_Model rsa = new RSA_Model(Integer.parseInt(args[3]));
					SecureRandom secureRandom = new SecureRandom();
		            KeyPairGenerator keyPairGenerator;
					try {
						keyPairGenerator = KeyPairGenerator.getInstance("RSA");
						keyPairGenerator.initialize(Integer.parseInt(args[3]), secureRandom);
						KeyPair keyPair = keyPairGenerator.genKeyPair();
						
						final PublicKey publicKey = keyPair.getPublic();
						final PrivateKey privateKey = keyPair.getPrivate();
						//��ȣȭ
						cTxt = encryptRSA(publicKey,args[1],args[2],args[3],args.length>4?args[4]:null);
						//��ȣȭ
						dTxt = decryptRSA(privateKey,cTxt,args[2],args[3],args.length>4?args[4]:null);
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
				
			}else if(gbn.equals("d")) {
				System.out.println("��ȣȭ �غ�����. !!!"+encryptAES(args[1],args[2],args[3],args.length>4?args[4]:null));
			}

		}else {
			System.out.println("���� : "+ errArgs);
		}
		
		System.out.println("�������������������������������������������");
    }  
	  	
	private static String cryptAES(String cryptoMode, String str, String crptType, String crptBits, String blckMode) {
		int CRYPT_MODE = cryptoMode.equals("e")?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE;
		System.out.println("CRYPT_MODE("+cryptoMode+") : "+CRYPT_MODE);
		Cipher cipher;
		String resultText = "";
		try {
			String cipherKey = getCipherKey("keeeeeey", crptBits);// ���Ʈ�ΰ�
			String cpStr = crptType.toUpperCase();
			if(crptType.toLowerCase().equals("aes") && blckMode!=null && !blckMode.equals("")) {
				cpStr += "/"+blckMode.toUpperCase();
				if(blckMode.toLowerCase().equals("cbc")) {
					cpStr +="/PKCS5Padding";
				}else if(blckMode.toLowerCase().equals("ctr")) {
					cpStr +="/NoPadding";
				}
				
			}
			System.out.println("Cipher Instance param: "+ cpStr);
			cipher = Cipher.getInstance(cpStr);
//			AES_Model aes= new AES_Model(cipherKey, crptType, cipher.getBlockSize());
			AES_Model aes= new AES_Model(cipherKey, crptType);
            if(blckMode==null
            		|| (blckMode.equals("") || blckMode.toLowerCase().equals("ecb"))) {
            	//IV no need
            	cipher.init(CRYPT_MODE, aes.getKeySpec());
            }else {
//            	cipher.init(CRYPT_MODE, aes.getScrtKey(), aes.getIvSpec());
            	cipher.init(CRYPT_MODE, aes.getKeySpec(), new IvParameterSpec(aes.getIv().getBytes()));
            	
            }
            byte[] crypted;
            if(cryptoMode.equals("e")) {
            	crypted = cipher.doFinal(str.getBytes("UTF-8"));
            	System.out.println("��ȣȭbyte"+crypted);
            	resultText = new String(DatatypeConverter.printBase64Binary(crypted));
            	System.out.println("�� :"+str + "\t��ȣȭ : "+ resultText);
            }else {
            	crypted = DatatypeConverter.parseBase64Binary(str);
            	System.out.println("��ȣȭbyte"+crypted);
            	resultText = new String(cipher.doFinal(crypted), "UTF-8");
            	System.out.println("��ȣ�� :"+str + "\t��ȣȭ�� �� : "+ resultText);
            }
 
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
		System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
		return resultText;
	}

	/**
	 * ��ȣȭ
	 * @param str
	 * @param crptType
	 * @param crptBits
	 * @param blckMode
	 * @return
	 */
	public static String encryptAES(String str, String crptType, String crptBits, String blckMode) {
		System.out.println("\n### ��ȣȭ����");
		Cipher cipher;
		String cTxt = "";
		try {
			String cpStr = crptType.toUpperCase();
			if(crptType.toLowerCase().equals("aes") && blckMode!=null && !blckMode.equals("")) {
				cpStr += "/"+blckMode.toUpperCase();
				if(blckMode.toLowerCase().equals("cbc")) {
					cpStr +="/PKCS5Padding";
				}else if(blckMode.toLowerCase().equals("ctr")) {
					cpStr +="/NoPadding";
				}
				
			}
			System.out.println("Cipher Instance param: "+ cpStr);
			cipher = Cipher.getInstance(cpStr);
//			AES_Model aes= new AES_Model(cipherKey, crptType, cipher.getBlockSize());
			String cipherKey = getCipherKey("keeeeeey", crptBits);// ���Ʈ�ΰ�
			AES_Model aes= new AES_Model(cipherKey, crptType);
            if(blckMode==null
            		|| (blckMode.equals("") || blckMode.toLowerCase().equals("ecb")|| blckMode.toLowerCase().equals("ctr"))) {
            	//IV no need
            	cipher.init(Cipher.ENCRYPT_MODE, aes.getKeySpec());
            }else {
//            	cipher.init(Cipher.ENCRYPT_MODE, aes.getScrtKey(), aes.getIvSpec());
            	cipher.init(Cipher.ENCRYPT_MODE, aes.getKeySpec(), new IvParameterSpec(aes.getIv().getBytes()));
            	
            }
 
            byte[] encrypted = cipher.doFinal(str.getBytes("UTF-8"));
            cTxt = new String(DatatypeConverter.printBase64Binary(encrypted));
 
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return cTxt;
	}

	/**
	 * AES ��ȣȭ
	 * @param str
	 * @param crptType
	 * @param crptBits
	 * @param blckMode
	 * @return
	 */
	public static String decryptAES(String str, String crptType, String crptBits, String blckMode) {
		System.out.println("\n### ��ȣȭ����");
		Cipher cipher;
		String dTxt="";
		try {
			String cipherKey = getCipherKey("keeeeeey", crptBits);// ���Ʈ�ΰ�
			String cpStr = crptType.toUpperCase();
			if(crptType.toLowerCase().equals("aes") && blckMode!=null && !blckMode.equals("")) {
				cpStr += "/"+blckMode.toUpperCase();
				if(blckMode.toLowerCase().equals("cbc")) {
					cpStr +="/PKCS5Padding";
				}else if(blckMode.toLowerCase().equals("ctr")) {
					cpStr +="/NoPadding";
				}
				
			}
			System.out.println("Cipher Instance param: "+ cpStr);
			cipher = Cipher.getInstance(cpStr);
//			AES_Model aes= new AES_Model(cipherKey, crptType, cipher.getBlockSize());
			AES_Model aes= new AES_Model(cipherKey, crptType);
            if(blckMode==null
            		|| (blckMode.equals("") || blckMode.toLowerCase().equals("ecb")|| blckMode.toLowerCase().equals("ctr"))) {
            	//IV no need
            	cipher.init(Cipher.DECRYPT_MODE, aes.getKeySpec());
            }else {
            	           	
//            	cipher.init(Cipher.DECRYPT_MODE, aes.getScrtKey(), aes.getIvSpec());
            	cipher.init(Cipher.DECRYPT_MODE, aes.getKeySpec(), new IvParameterSpec(aes.getIv().getBytes("UTF-8")));
            }
 
            byte[] decrypted = DatatypeConverter.parseBase64Binary(str);
            dTxt = new String(cipher.doFinal(decrypted), "UTF-8");
 
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return dTxt;
	}

	public static String encryptRSA(PublicKey publicKey, String str, String bits, String crptType, String blckMode) throws UnsupportedEncodingException {
		System.out.println("\n### ��ȣȭ����");
//		System.out.println("����Ű : "+ new String(publicKey.getEncoded(), "UTF-8"));
		//TODO
//		RSA�� (Key bit�� / 8) - 11 ��ŭ�� ����Ʈ��ŭ�� ��/��ȣȭ �Ҽ� �ִ�. 
//		�̺κ� ���� ���� �߰��ؾ� �Ұ�.
		System.out.println("�� : "+str.getBytes().length+" bytes");
		Cipher cipher;
		String cTxt = "";
		byte[] encrypted;
		try {

			cipher = Cipher.getInstance(crptType.toUpperCase());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			encrypted = cipher.doFinal(str.getBytes("UTF-8"));
			cTxt += new String(DatatypeConverter.printBase64Binary(encrypted));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		System.out.println("�� : "+str+"\n��ȣ�� : "+ cTxt);
		return cTxt;
	}

	public static String decryptRSA(PrivateKey privateKey, String cTxt, String crptType, String crptBits, String blckMode) throws UnsupportedEncodingException {
		System.out.println("\n### ��ȣȭ����");
		System.out.println("��ȣ��ũ�� : "+cTxt.getBytes().length+" bytes");
//		System.out.println("����Ű : "+ new String(privateKey.getEncoded(), "UTF-8"));
		Cipher cipher;
		String dTxt = "";
		try {
			cipher = Cipher.getInstance(crptType.toUpperCase());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decrypted = DatatypeConverter.parseBase64Binary(cTxt);
			dTxt = new String(cipher.doFinal(decrypted), "utf-8");
		} catch (Exception e) {
//		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
//				| IllegalBlockSizeException | BadPaddingException
//				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		System.out.println("��ȣ�� : "+cTxt+"\n��ȣȭ�� : "+ dTxt);
		return dTxt;
	}

	/**
	 * ��ȣȭ Ű ����.
	 * @param bitStr
	 * @return
	 */
	private static String getCipherKey(String key, String bitStr) {
		System.out.println("### ��ȣȭŰ����");
		int bits = Integer.parseInt(bitStr);
		int keylen = bits/8;
		if(key.length() > keylen) {
			key.substring(0, keylen);
		}else if ((key.length() < keylen)) {
			key = pad(key,keylen);
		}
		System.out.println("������ ��ȣȭ Ű : " + key);
		return key;
	}

	/**
	 * Ű�� ��Ʈ���� �����ִ� �Լ�. ��ȣȭbit�� ���� �е��Ѵ�.
	 * @param key : �־��� Ű
	 * @param keylen : ��ȣȭ��Ʈ-> ����Ʈ�� �� int
	 * @return
	 */
	private static String pad(String key, int keylen) {
		int padCnt = keylen - key.length();
		for(int i = 0 ; i < padCnt ; i++) {
			key += "0";
		}
		System.out.println("�е��Ȱ�� ::"+key);
		return key;
	}

	/**
	 * �Ķ���� ��ȿ��üũ
	 * @param args
	 * @return
	 */
	private static Map<String, String> getValidity(String[] args) {
		
//		System.out.println("\n### main �Լ� �Ķ���� ��ȿ�� �˻� a �� �Ķ����");
		
		Map<String, String> validMap = new HashMap<String, String>();
		
		String isValid = "Y";
		String errArgs ="";
		if(args != null && args.length>=4) {//�ʼ��Ķ����
			// args[0] ��ȣȭ/ ��ȣȭ 
			// args[1] ��ȣȭ�� ��
			// args[2] AES/ RSA
			// args[3] ��ȣȭ ��Ʈ��
			// args[4] ��ϸ��� 2���� ��ȿ�ϰ�  aes �϶���, cbc/ctr
			
			if(!(args[0].equals("e") || args[0].equals("d"))) errArgs += "args[0] ";
			if(args[1]==null && args[1].equals("")) errArgs += "args[1] ";
			if((args[2].toLowerCase().equals("aes")||args[2].toLowerCase().equals("rsa"))) {
				if(args[2].toLowerCase().equals("aes")) {
					if(!(args[3].equals("128")||args[3].equals("192")||args[3].equals("256"))) errArgs += "args[3] ";
					
					if(args.length>4 && !(args[4].toLowerCase().equals("cbc")||args[4].toLowerCase().equals("ctr"))) errArgs += "args[4] ";
				}
				if(args[2].toLowerCase().equals("rsa")) {
					if(!(args[3].equals("1024")||args[3].equals("2048"))) errArgs += "args[3] ";
					if(args.length>4) args[4] = null; System.out.println("args[4] ��ϸ�尡 �ƴմϴ�. ���õǾ����ϴ�.");
					
				}
	
			}else {
				errArgs += "args[2] ";
			}
			if(!errArgs.equals("")) isValid = "N";
		}else {
			isValid = "N";
			errArgs = "�Ķ���� �迭�� ���� �־��ּ���.";
		}
		
//		int i = 0;
//		for(String arg : args) {
//			
//			System.out.println(i+") "+arg);
//			i++;
//		}
		validMap.put("isValid", isValid);
		validMap.put("errArgs", errArgs);
		return validMap;
	}

	/**
		 * RSA ��ȣȭ
		 * @param publicKey 
		 * @param str
		 * @param crptType
		 * @param crptBits
		 * @param blckMode
		 * @return
		 * @throws UnsupportedEncodingException 
		 */
		public static String encryptRSA2(PublicKey publicKey, String str, String crptType, String crptBits, String blckMode) throws UnsupportedEncodingException {
			System.out.println("\n### ��ȣȭ����");
	//		System.out.println("����Ű : "+ new String(publicKey.getEncoded(), "UTF-8"));
			//TODO
	//		RSA�� (Key bit�� / 8) - 11 ��ŭ�� ����Ʈ��ŭ�� ��/��ȣȭ �Ҽ� �ִ�. 
	//		�̺κ� ���� ���� �߰��ؾ� �Ұ�.
			System.out.println("�� : "+str.getBytes().length+" bytes");
			int cblockSize = (Integer.parseInt(crptBits)/8) - 11 ;//�ѹ��� ��ȣȭ �Ҽ� �ִ� ũ�� byte
			System.out.println("��ȣȭ ����ũ�� : "+cblockSize+" bytes");
			byte[] encrypted;
			int iterNum = 1;
			int modMum = 0;
			if(str.getBytes().length>cblockSize) {
				//�߶� �۾��ؾ���.
				iterNum = str.getBytes().length / cblockSize;
				modMum = str.getBytes().length % cblockSize;
				iterNum += modMum==0?0:1;
			}
			Cipher cipher;
			String cTxt = "";
			try {
				byte[] strTobytes = str.getBytes();
				for(int i=0;i<iterNum;i++) {
					encrypted = new byte[cblockSize];
					String blockedStr = "";
					int stIdx = 0*i;
					int edIdx = cblockSize*i;
					for(int j=stIdx;j<edIdx;j++) {
						encrypted[i] = strTobytes[j];
					}
					blockedStr = new String(encrypted,"UTF-8");
					cipher = Cipher.getInstance(crptType.toUpperCase());
					cipher.init(Cipher.ENCRYPT_MODE, publicKey);
					
					encrypted = cipher.doFinal(blockedStr.getBytes("UTF-8"));
					cTxt += new String(DatatypeConverter.printBase64Binary(encrypted));
				}
				
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
					| IllegalBlockSizeException | BadPaddingException
					| UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			System.out.println("�� : "+str+"\n��ȣ�� : "+ cTxt);
			return cTxt;
		}

	/**
		 * RSA ��ȣȭ
		 * @param privateKey 
		 * @param str
		 * @param crptType
		 * @param crptBits
		 * @param blckMode
		 * @return
		 * @throws UnsupportedEncodingException 
		 */
		public static String decryptRSA2(PrivateKey privateKey, String str, String crptType, String crptBits, String blckMode) throws UnsupportedEncodingException {
			System.out.println("\n### ��ȣȭ����");
			System.out.println("��ȣ�� : "+str.getBytes().length+" bytes");
	//		System.out.println("����Ű : "+ new String(privateKey.getEncoded(), "UTF-8"));
			int cblockSize = (Integer.parseInt(crptBits)/8) - 11 ;//�ѹ��� ��ȣȭ �Ҽ� �ִ� ũ�� byte
			System.out.println("��ȣȭ ����ũ�� : "+cblockSize+" bytes");
			byte[] decrypted;
			int iterNum = 1;
			int modMum = 0;
			if(str.getBytes().length>cblockSize) {
				//�߶� �۾��ؾ���.
				iterNum = str.getBytes().length / cblockSize;
				modMum = str.getBytes().length % cblockSize;
				iterNum += modMum==0?0:1;
			}
			System.out.println("�ڸ����ڿ�������: "+iterNum);
			Cipher cipher;
			String dTxt = "";
			try {
	//			byte[] strTobytes = str.getBytes();
	//			for(int i=0;i<iterNum;i++) {
	//				decrypted = new byte[cblockSize];
	//				String blockedStr = "";
	//				int stIdx = 0*i;
	//				int edIdx = cblockSize*(i+1);
	//				for(int j=stIdx;j<edIdx;j++) {
	//					decrypted[j] = strTobytes[j];
	//				}
	//				cipher = Cipher.getInstance(crptType.toUpperCase());
	//				cipher.init(Cipher.DECRYPT_MODE, privateKey);
	//				
	//				blockedStr = new String(DatatypeConverter.printBase64Binary(decrypted));
	//				decrypted = DatatypeConverter.parseBase64Binary(blockedStr); //cipher.doFinal(blockedStr.getBytes("UTF-8"));
	//				decrypted = cipher.doFinal(decrypted);
	//				System.out.println("decrypted.length : "+decrypted.length);
	//				dTxt += new String(decrypted,"UTF-8");
	//	            
	//			}
				cipher = Cipher.getInstance(crptType.toUpperCase());
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
		        decrypted = DatatypeConverter.parseBase64Binary(str);
		        dTxt = new String(cipher.doFinal(decrypted), "UTF-8");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
					| IllegalBlockSizeException | BadPaddingException
					| UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			System.out.println("��ȣ�� : "+str+"\n�� : "+ dTxt);
			return dTxt;
		}
}
