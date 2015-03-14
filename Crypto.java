import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Util.HomomorphicProperty;
import CryptoFac.CryptoCreator;
import CryptoFac.CryptoFactory;

public class Crypto {

	private static final int bitLen = 512;
	private static String name[] = { "", "DESede", "ECIES", "ElGamal", "RSA",
			"Paillier", "ExponentialElGamal" };

	public static void main(String[] arg) {
		Scanner scanner = new Scanner(System.in);
		String choice = null;

		byte[] clearTextBytes = BigInteger.probablePrime(5, new SecureRandom())
				.toByteArray();

		while (true) {
			System.out.println("\nPlease Select a Crypto:");
			System.out.println("\n1. DESede");
			System.out.println("2. ECIESC");
			System.out.println("3. ElGamal");
			System.out.println("4. RSA");
			System.out.println("5. Paillier");
			System.out.println("6. ExponentialElGamal");

			System.out.println("\nPress \"-1\" to quit.");

			choice = scanner.nextLine();

			int num = Integer.parseInt(choice);
			if (num == -1) {
				break;
			}

			if (num > 6 || num < 0) {
				System.out.println("Sorry, Wrong choice");
				continue;
			}

			Security.addProvider(new BouncyCastleProvider());

			CryptoFactory crypto = CryptoCreator.create(name[num], bitLen);

			if (crypto == null) {
				System.out.println("Create Crypto class failed.");
				return;
			}

			System.out.println("Current Crypto: " + crypto.getCryptoName());

			System.out.println("Input Length: "
					+ new BigInteger(clearTextBytes).bitLength());

			System.out.println("Key Size: " + crypto.getKeySize());

			System.out.println("Before encryption: "
					+ new BigInteger(clearTextBytes));

			long start = System.currentTimeMillis();

			byte[] cipherTextBytes = crypto.encrypto(clearTextBytes);

			long during = System.currentTimeMillis() - start;
			System.out.println("Encryption Time: " + during);

			start = System.currentTimeMillis();

			byte[] decryptedTextBytes = crypto.decrypto(cipherTextBytes);

			during = System.currentTimeMillis() - start;
			System.out.println("Decryption Time: " + during);

			System.out.println("after decrypto: "
					+ new BigInteger(decryptedTextBytes));

			// Check Homomorphic Property
			HomomorphicProperty homo = new HomomorphicProperty(name[num],
					bitLen);
			// Addictive
			homo.checkAddHomomorphic();
			// Multiplicative
			homo.checkMultiHomomorphic();

		}
		scanner.close();

	}
}
