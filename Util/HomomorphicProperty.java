package Util;

import java.math.BigInteger;
import java.security.SecureRandom;

import CryptoFac.CryptoCreator;
import CryptoFac.CryptoFactory;

public class HomomorphicProperty {
	private CryptoFactory crypto1;
	private CryptoFactory crypto2;
	private BigInteger clearText1, clearText2;
	private String name;
	private SecureRandom random;
	private int bitLen;
	public HomomorphicProperty(String name, int bitLen){
		this.name=name;
		crypto1=CryptoCreator.create(name, bitLen);
		
		
		this.bitLen=bitLen;
		
		SecureRandom random=new SecureRandom();
		clearText1=new BigInteger(bitLen, random);
		clearText2=new BigInteger(bitLen, random);
	}
	
	public void checkAddHomomorphic(){
		byte[] cipherText1=crypto1.encrypto(clearText1.toByteArray());
		
		crypto2=crypto1.getCopy();
		byte[] cipherText2=crypto2.encrypto(clearText2.toByteArray());
		
		CryptoFactory crypto=crypto1.getCopy(crypto2);
		
		byte[] temp=crypto.encrypto(clearText1.add(clearText2).toByteArray());
		
		if(crypto1.multiply(crypto2).theSameWith(crypto)){
			System.out.println("E(X1)*E(X2)=E(X1+X2)");
		}
		else{
			System.out.println("E(X1)*E(X2)!=E(X1+X2)");
		}
		
	}
	public void checkMultiHomomorphic(){
		byte[] cipherText1=crypto1.encrypto(clearText1.toByteArray());
		
		crypto2=crypto1.getCopy();
		byte[] cipherText2=crypto2.encrypto(clearText2.toByteArray());
		
		CryptoFactory crypto=crypto1.getCopy(crypto2);
		
		byte[] temp=crypto.encrypto(clearText1.multiply(clearText2).toByteArray());
		
		if(crypto1.multiply(crypto2).theSameWith(crypto)){
			System.out.println("E(X1)*E(X2)=E(X1*X2)");
		}
		else{
			System.out.println("E(X1)*E(X2)!=E(X1*X2)");
		}
	}
}
