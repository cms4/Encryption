package Cryptos;

import java.math.BigInteger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import CryptoFac.CryptoFactory;

//DESedeCrypto using Bouncy Castle APIs, Non-Homomorphic Crypto
public class DESedeCrypto extends CryptoFactory {
	private KeyGenerator keyGenerator;
	private SecretKey secretKey;
	private Cipher cipher;
	private byte[] cipherText;

	private byte[] cipherBytes;
	private int bitLen = 168;

	public DESedeCrypto() {
		name = "DESede";
		try {
			keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(bitLen);
			secretKey = keyGenerator.generateKey();
			cipher = Cipher.getInstance("DESede");

		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	public DESedeCrypto(Cipher cipher, SecretKey secretKey) {
		name = "DESede";
		this.cipher = cipher;
		this.secretKey = secretKey;
	}

	@Override
	public CryptoFactory getCopy() {
		return new DESedeCrypto(cipher, secretKey);
	}

	@Override
	public CryptoFactory getCopy(CryptoFactory c1) {
		return new DESedeCrypto(cipher, secretKey);
	}

	public byte[] encrypto(byte[] clearTextBytes) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			cipherBytes = cipher.doFinal(clearTextBytes);
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
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] decryptedBytes = cipher.doFinal(cipherBytes);
			return decryptedBytes;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public String getCryptoName() {
		return name;
	}

	@Override
	public int getKeySize() {
		return bitLen;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public BigInteger multiResult;

	@Override
	public CryptoFactory multiply(CryptoFactory c1) {
		multiResult = new BigInteger(this.getCipherText())
				.multiply(new BigInteger(((DESedeCrypto) c1).getCipherText()));
		return this;
	}

	@Override
	public boolean theSameWith(CryptoFactory c1) {
		if (this.multiResult.equals(new BigInteger(((DESedeCrypto) c1)
				.getCipherText()))) {
			return true;
		}
		return false;
	}

}
