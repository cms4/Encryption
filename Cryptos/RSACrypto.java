package Cryptos;

import java.math.BigInteger;
import java.security.SecureRandom;

import CryptoFac.CryptoFactory;

//RSA Crypto
public class RSACrypto extends CryptoFactory {
	private BigInteger p, q;
	private BigInteger n;
	private BigInteger euler;
	private BigInteger e, d;
	private SecureRandom random;
	private byte[] cipherText;

	public RSACrypto(int bitLen) {
		this.bitLen = bitLen;

		name = "RSA";

		random = new SecureRandom();
		p = BigInteger.probablePrime(bitLen, random);
		q = BigInteger.probablePrime(bitLen, random);

		n = p.multiply(q);
		euler = n.subtract(p.add(q).subtract(BigInteger.ONE));

		while (true) {
			e = BigInteger.probablePrime(bitLen, random);
			if (e.compareTo(euler) < 0 && e.gcd(euler).intValue() == 1) {
				break;
			}
		}
		d = e.modInverse(euler);

	}

	public RSACrypto(String name, int bitLen, SecureRandom random,
			BigInteger p, BigInteger q, BigInteger e, BigInteger n,
			BigInteger euler, BigInteger d) {
		this.name = name;
		this.bitLen = bitLen;
		this.random = random;
		this.p = p;
		this.q = q;
		this.n = n;
		this.euler = euler;
		this.d = d;
		this.e = e;
	}

	@Override
	public CryptoFactory getCopy() {

		return new RSACrypto(name, bitLen, random, p, q, e, n, euler, d);
	}

	@Override
	public CryptoFactory getCopy(CryptoFactory c1) {
		return new RSACrypto(name, bitLen, random, p, q, e, n, euler, d);
	}

	@Override
	public byte[] encrypto(byte[] clearText) {
		BigInteger message = new BigInteger(clearText);
		if (message.compareTo(n) > 0) {
			System.out.println("Message is too large for current n");
			return null;
		}
		BigInteger cipherText = message.modPow(e, n);
		this.cipherText = cipherText.toByteArray();
		return cipherText.toByteArray();
	}

	@Override
	public byte[] decrypto(byte[] cipherText) {
		BigInteger c = new BigInteger(cipherText);

		BigInteger m = c.modPow(d, n);

		return m.toByteArray();
	}

	@Override
	public String getCryptoName() {

		return name;
	}

	@Override
	public int getKeySize() {

		return n.bitLength();
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public BigInteger multiResult;

	@Override
	public CryptoFactory multiply(CryptoFactory c1) {
		multiResult = new BigInteger(this.getCipherText()).multiply(
				new BigInteger(((RSACrypto) c1).getCipherText())).mod(n);
		return this;
	}

	@Override
	public boolean theSameWith(CryptoFactory c1) {
		// System.out.println("multiResult="+multiResult);
		// System.out.println("new BigInteger(((RSACrypto)c1).getCipherText())="+new
		// BigInteger(((RSACrypto)c1).getCipherText()));
		if (this.multiResult.equals(new BigInteger(((RSACrypto) c1)
				.getCipherText()))) {
			return true;
		}
		return false;
	}

}
