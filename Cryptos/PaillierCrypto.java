package Cryptos;

import java.math.BigInteger;
import java.security.SecureRandom;

import CryptoFac.CryptoFactory;

//Paillier Crypto
public class PaillierCrypto extends CryptoFactory {
	private BigInteger p, q, lambda;
	private BigInteger n, nSquare;
	private BigInteger g, r;
	private SecureRandom random;
	private byte[] cipherText;

	public PaillierCrypto(int bitLen) {
		this.bitLen = bitLen;
		name = "Paillier";
		random = new SecureRandom();
		keyGeneration();
	}

	public void keyGeneration() {

		p = BigInteger.probablePrime(bitLen / 2, random);
		q = BigInteger.probablePrime(bitLen / 2, random);

		lambda = (p.subtract(BigInteger.ONE).multiply(q
				.subtract(BigInteger.ONE))).divide(p.subtract(BigInteger.ONE)
				.gcd(q.subtract(BigInteger.ONE)));

		n = p.multiply(q);
		nSquare = n.multiply(n);
		g = new BigInteger("2");

		if (!g.modPow(lambda, nSquare).subtract(BigInteger.ONE).divide(n)
				.gcd(n).equals(BigInteger.ONE)) {
			System.out.println("Bad g.");
			System.exit(1);
		}
		r = new BigInteger(bitLen, random);
	}

	public PaillierCrypto(String name, int bitLen, SecureRandom random,
			BigInteger p, BigInteger q, BigInteger lambda, BigInteger n,
			BigInteger nSquare, BigInteger g, BigInteger r) {
		this.name = name;
		this.bitLen = bitLen;
		this.random = random;
		this.p = p;
		this.q = q;
		this.lambda = lambda;
		this.n = n;
		this.nSquare = nSquare;
		this.g = g;
		this.r = r;
	}

	@Override
	public CryptoFactory getCopy() {
		return new PaillierCrypto(name, bitLen, random, p, q, lambda, n,
				nSquare, g, r);
	}

	public CryptoFactory getCopy(CryptoFactory c1) {
		return new PaillierCrypto(name, bitLen, random, p, q, lambda, n,
				nSquare, g, this.r.multiply(((PaillierCrypto) c1).getR()));
	}

	public BigInteger getR() {
		return this.r;
	}

	@Override
	public byte[] encrypto(byte[] clearText) {
		BigInteger text = new BigInteger(clearText).mod(nSquare);
		byte[] cipherText = g.modPow(text, nSquare)
				.multiply(r.modPow(n, nSquare)).mod(nSquare).toByteArray();
		this.cipherText = cipherText;
		return cipherText;
	}

	@Override
	public byte[] decrypto(byte[] cipherText) {
		BigInteger u = g.modPow(lambda, nSquare).subtract(BigInteger.ONE)
				.divide(n).modInverse(n);
		byte[] plainText = new BigInteger(cipherText).modPow(lambda, nSquare)
				.subtract(BigInteger.ONE).divide(n).multiply(u).mod(n)
				.toByteArray();
		return plainText;
	}

	@Override
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
		multiResult = new BigInteger(this.getCipherText()).multiply(
				new BigInteger(((PaillierCrypto) c1).getCipherText())).mod(
				nSquare);
		return this;
	}

	@Override
	public boolean theSameWith(CryptoFactory c1) {
		if (this.multiResult.equals(new BigInteger(((PaillierCrypto) c1)
				.getCipherText()))) {
			return true;
		}
		return false;
	}

}
