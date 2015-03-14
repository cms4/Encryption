package Cryptos;

import java.math.BigInteger;
import java.security.SecureRandom;

import Util.Pair;
import CryptoFac.CryptoFactory;

//ElGamal Crypto
public class ElGamalCrypto extends CryptoFactory {
	private SecureRandom random;
	private BigInteger modulus;
	public Pair cipherPair;
	private BigInteger q, g;
	private BigInteger x;
	private BigInteger h;

	private BigInteger y;

	public ElGamalCrypto(int bitLen) {
		this.bitLen = bitLen;
		name = "ElGamal";
		random = new SecureRandom();

		q = BigInteger.probablePrime(bitLen, random);
		g = BigInteger.probablePrime(bitLen, random);
		modulus = BigInteger.probablePrime(bitLen, random);

		x = getRandomValue();
		h = g.modPow(x, modulus);

		y = getRandomValue();
	}

	public ElGamalCrypto(String name, int bitLen, SecureRandom random,
			BigInteger q, BigInteger g, BigInteger modulus, BigInteger x,
			BigInteger h, BigInteger y) {
		this.name = name;
		this.bitLen = bitLen;
		this.random = random;
		this.modulus = modulus;
		this.q = q;
		this.g = g;
		this.x = x;
		this.h = h;
		this.y = y;
	}

	@Override
	public CryptoFactory getCopy() {

		return new ElGamalCrypto(name, bitLen, random, q, g, modulus, x, h, y);
	}

	@Override
	public CryptoFactory getCopy(CryptoFactory c1) {
		return new ElGamalCrypto(name, bitLen, random, q, g, modulus, x, h,
				this.y.add(((ElGamalCrypto) c1).getY()));
	}

	public BigInteger getY() {
		return this.y;
	}

	@Override
	public byte[] encrypto(byte[] clearText) {

		BigInteger c1 = g.modPow(y, modulus);

		BigInteger s = h.modPow(y, modulus);
		BigInteger c2 = new BigInteger(clearText).mod(modulus).multiply(s)
				.mod(modulus);

		byte[] c1Array = c1.toByteArray();
		byte[] c2Array = c2.toByteArray();
		cipherPair = new Pair(c1Array, c2Array);

		return clearText;
	}

	@Override
	public byte[] decrypto(byte[] cipherText) {

		BigInteger c1 = new BigInteger(cipherPair.getC1());
		BigInteger c2 = new BigInteger(cipherPair.getC2());

		BigInteger s = c1.modPow(x, modulus);

		byte[] plainText = c2.multiply(s.modInverse(modulus)).mod(modulus)
				.toByteArray();

		return plainText;

	}

	@Override
	public String getCryptoName() {
		return name;
	}

	private BigInteger getRandomValue() {
		while (true) {
			BigInteger result = BigInteger.probablePrime(bitLen, random);
			if (result.compareTo(q) < 0) {
				return result;
			}
		}
	}

	@Override
	public int getKeySize() {
		return bitLen;
	}

	public Pair multiplyPair;

	@Override
	public CryptoFactory multiply(CryptoFactory c1) {
		byte[] c1_pair = new BigInteger(this.cipherPair.getC1())
				.multiply(
						new BigInteger(((ElGamalCrypto) c1).cipherPair.getC1()))
				.mod(modulus).toByteArray();
		byte[] c2_pair = new BigInteger(this.cipherPair.getC2())
				.multiply(
						new BigInteger(((ElGamalCrypto) c1).cipherPair.getC2()))
				.mod(modulus).toByteArray();
		this.multiplyPair = new Pair(c1_pair, c2_pair);

		return this;
	}

	@Override
	public boolean theSameWith(CryptoFactory c1) {

		if (!new BigInteger(this.multiplyPair.getC1()).equals(new BigInteger(
				((ElGamalCrypto) c1).cipherPair.getC1()))) {
			return false;
		}
		if (!new BigInteger(this.multiplyPair.getC2()).equals(new BigInteger(
				((ElGamalCrypto) c1).cipherPair.getC2()))) {
			return false;
		}
		return true;
	}

}
