package CryptoFac;

//Crypto Factory
public abstract class CryptoFactory {
	public String name;
	public int bitLen;

	public CryptoFactory() {
	}

	public CryptoFactory(int bitLen) {
	}

	public abstract byte[] encrypto(byte[] clearText);

	public abstract byte[] decrypto(byte[] cipherText);

	public abstract String getCryptoName();

	public abstract int getKeySize();

	public abstract CryptoFactory multiply(CryptoFactory c1);

	public abstract boolean theSameWith(CryptoFactory c1);

	public abstract CryptoFactory getCopy();

	public abstract CryptoFactory getCopy(CryptoFactory c1);
}
