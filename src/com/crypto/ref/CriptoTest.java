package com.crypto.ref;
import java.util.Scanner;

public class CriptoTest {
	public static void main(String[] args) {
		String plainText="";
		String crpt="";
		String crpt_bits="";
		String crpt_mode="";
		String[] crptArr = new String[4];
		
		double height;
		String intro;
		String buffer;
		
		String warnMsg = "�߸��� �����Դϴ�. �ٽ� �Է����ּ���.";
		
		Scanner sc = new Scanner(System.in);
		System.out.println("��ȣȭ�� ������ �Է��ϼ���.");
		plainText = sc.nextLine();
		crptArr[0] = plainText;
//		PlainText = getInputKey(sc);
		System.out.println("��ȣȭ ������ �����ϼ���.(Ű�����Է�)");
		System.out.println("1. AES\t2. RSA");
		try {
			String temp = sc.nextLine();
			int crptAscii = System.in.read();//ascii �ڵ�
			System.out.println("temp : "+temp);
			System.out.println("crptAscii : "+crptAscii);
			boolean goStop = true;
			while(goStop) {
				
				if(crptAscii==49) {
					crpt="AES";
					System.out.println("���θ�带 �������ֽʽÿ�.");
					System.out.println("1. AES-128\t2. AES-192\t3. AES-256\t4. AES-CBC-256\t5. GCM");
					sc.nextLine();
					crptAscii = System.in.read();//ascii �ڵ�
					char inputKey = (char) crptAscii;
					System.out.println("crptAscii : "+crptAscii+"\tinputKey : "+inputKey);
					if(crptAscii==49) {
						
						crpt_bits="128";
						
					}else if(crptAscii==50) {
						
						crpt_bits="192";
						
					}else if(crptAscii==51) {
						
						crpt_bits="256";
						
					}else if(crptAscii==52) {
						
						crpt_bits="256";
						crpt_mode="CBC";
						
					}else if(crptAscii==53) {
						
						crpt_bits="128";
						crpt_mode="CTR";
					}else if(crptAscii==27) {//escŰ
						System.out.println("�����մϴ�.");
						System.exit(0);	
					}else {
						System.out.println(warnMsg);
					}
					goStop = false;
					
				}else if(crptAscii==50) {
					crpt="RSA";
					System.out.println("���θ�带 �������ֽʽÿ�.");
					System.out.println("1. RSA-1024\t2. RSA-2048");
					sc.nextLine();
					crptAscii = System.in.read();//ascii �ڵ�
					System.out.println("crptAscii : "+crptAscii);
					if(crptAscii==49) {
						
						crpt_bits="1024";
						
					}else if(crptAscii==50) {
						
						crpt_bits="2048";
					}else if(crptAscii==27) {//escŰ
						System.out.println("�����մϴ�.");
						System.exit(0);	
					}else {
						System.out.println(warnMsg);
					}
					goStop = false;
				}else if(crptAscii==27) {//escŰ
					System.out.println("�����մϴ�.");
					System.exit(0);
				}else {
					System.out.println(warnMsg);
					System.out.println("�����մϴ�.");
					break;
				}
				
				crptArr[1] = crpt;
				crptArr[2] = crpt_bits;
				crptArr[3] = crpt_mode;
				goEncript(sc, crptArr);
			}
			
		} catch (Exception e) {
			// TODO: handle exception
		}
		
	}

	private static void goEncript(Scanner sc, String[] crptArr) {
		// TODO Auto-generated method stub
		System.out.println("excute goEncript!!");
		for(String arr:crptArr) {
			System.out.println("��� : "+arr);
		}
		try {
			CryptoAES c = new CryptoAES();
			String cipherText = c.encription(crptArr[0],crptArr[1],crptArr[2],crptArr[3]);
			if(cipherText!=null && cipherText.length()>0) {
				System.out.println("��ȣȭ�Ͻðڽ��ϱ�?? Y or N");
				sc.nextLine();
				int input = System.in.read();//ascii �ڵ�
				System.out.println("crptAscii : "+input);
				while(true) {
					if(input==89||input==121) {
						
						break;
					}else if(input==89||input==121) {
						break;
					}else {
						System.out.println("�ٽ� �Է����ּ���.");
						sc.nextLine();
					}
				}
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		
	
	}

	private static String getInputKey(Scanner sc) {
		sc.next();
		return null;
	}
}
