package CryptoFac;

import Cryptos.DESedeCrypto;
import Cryptos.ECIESCrypto;
import Cryptos.ElGamalCrypto;
import Cryptos.ExponentialElGamalCrypto;
import Cryptos.PaillierCrypto;
import Cryptos.RSACrypto;

//Create Relative Crypto Class
public class CryptoCreator {
	public static CryptoFactory create(String name, int bitLen) {
		if (name.equals("DESede")) {
			return new DESedeCrypto();
		} else if (name.equals("ECIES")) {
			return new ECIESCrypto();
		} else if (name.equals("ElGamal")) {
			return new ElGamalCrypto(bitLen);
		} else if (name.equals("RSA")) {
			return new RSACrypto(bitLen);
		} else if (name.equals("Paillier")) {
			return new PaillierCrypto(bitLen);
		} else if (name.equals("ExponentialElGamal")) {
			return new ExponentialElGamalCrypto(bitLen);
		}
		return null;
	}
}
