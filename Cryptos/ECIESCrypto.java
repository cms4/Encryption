package Cryptos;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;

import CryptoFac.CryptoFactory;

//ECIES Crypto using Bouncy Castle APIs, Non-Homomorphic Crypto
public class ECIESCrypto extends CryptoFactory {
	private KeyPairGenerator keyGenerator;
	private KeyPair keyPair;
	private Cipher cipher;
	private ECPublicKey pubKey;
	private ECPrivateKey privKey;
	private SecureRandom random;
	private byte[] cipherText;

	public ECIESCrypto() {
		this.name = "ECIES";

		try {
			keyGenerator = KeyPairGenerator.getInstance("ECIES", "BC");

			keyPair = keyGenerator.generateKeyPair();
			pubKey = (ECPublicKey) keyPair.getPublic();
			privKey = (ECPrivateKey) keyPair.getPrivate();

			cipher = Cipher.getInstance("ECIES");
			random = new SecureRandom();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public ECIESCrypto(Cipher cipher, ECPublicKey pubKey, ECPrivateKey privKey) {
		this.cipher = cipher;
		this.pubKey = pubKey;
		this.privKey = privKey;
	}

	@Override
	public CryptoFactory getCopy() {

		return new ECIESCrypto(this.cipher, this.pubKey, this.privKey);
	}

	@Override
	public CryptoFactory getCopy(CryptoFactory c1) {
		return new ECIESCrypto(this.cipher, this.pubKey, this.privKey);
	}

	@Override
	public String getCryptoName() {
		return name;
	}

	@Override
	public byte[] encrypto(byte[] clearText) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
			byte[] cipherBytes = cipher.doFinal(clearText);
			this.cipherText = cipherBytes;
			return cipherBytes;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public byte[] decrypto(byte[] cipherText) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			byte[] decryptedBytes = cipher.doFinal(cipherText);
			return decryptedBytes;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public int getKeySize() {
		return 0;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public BigInteger multiResult;

	@Override
	public CryptoFactory multiply(CryptoFactory c1) {
		multiResult = new BigInteger(this.getCipherText())
				.multiply(new BigInteger(((ECIESCrypto) c1).getCipherText()));
		return this;
	}

	@Override
	public boolean theSameWith(CryptoFactory c1) {
		if (this.multiResult.equals(new BigInteger(((ECIESCrypto) c1)
				.getCipherText()))) {
			return true;
		}
		return false;
	}

}
