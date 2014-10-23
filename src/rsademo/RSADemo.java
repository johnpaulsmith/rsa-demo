/**
 *
 * @author: John Paul Smith
 *
 * CS-490: Cryptography - Keene State College
 *
 * A simple demonstration of the RSA cryptosystem.
 */
package rsademo;

import java.math.BigInteger;
import java.util.Random;

public class RSADemo {

    public static void main(String[] args) {

        simpleRSADemo();
    }

    public static void simpleRSADemo() {

        Random r = new Random();

        String plainTextMessage = "Number theory FTW!";      

        /**
         * The length of n in bits.
         */
        final int BIT_LENGTH = 1024;
        
        /**
         * Ensure that plainTextMessage's mapping into a number < 2^BIT_LENGTH.
         */

        /**
         * The largest Fermat number that is also a prime number is a good
         * choice for e in practice.
         */
        final BigInteger LFP = new BigInteger("65537");

        /**
         * Find two distinct prime numbers p and q.
         */
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH >> 1, r);

        BigInteger q = BigInteger.probablePrime(BIT_LENGTH >> 1, r);

        /**
         * Ensure q != p.
         */
        while (p.compareTo(q) == 0) {

            q = BigInteger.probablePrime(BIT_LENGTH / 2, r);
        }

        System.out.println("RSA Demo\n\nThe key length is " + BIT_LENGTH + " bits\n");
        
        System.out.println("p: " + p + "\n\nq: " + q + "\n");

        /**
         * Compute n such that n = pq.
         */
        BigInteger n = p.multiply(q);

        System.out.println("n: " + n + "\n");

        /**
         * Compute the result of Euler's Totient Function on n. Since p and q
         * are prime numbers this result is simply (p-1)(q-1).
         */
        BigInteger f = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        System.out.println("f: " + f + "\n");

        /**
         * Select e such that 1 < e < f and gcd(f, e) = 1. e and f are coprime.
         */
        BigInteger e = (f.compareTo(LFP) <= 0 ? new BigInteger("17") : LFP);

        System.out.println("e: " + e + "\n");

        /**
         * Compute d such that de - 1 mod f = 0. de is congruent to 1 mod f.
         * d is the multiplicative inverse of e mod f.
         */
        BigInteger d = modMultInv(e, f);

        if (d.compareTo(BigInteger.ZERO) == 0) {

            throw new java.lang.RuntimeException("Something went wrong because"
                    + "there is no multiplicative inverse mod " + f + " for "
                    + e);

        } else if (d.compareTo(BigInteger.ZERO) < 0) {    

            /**
             * If the multiplicative inverse is negative, convert to the
             * smallest positive multiplicative inverse. The inverses are often
             * negative when calculated using the extended Euclidean algorithm.
             */
            do {
                
                d = d.add(f);

            } while (d.compareTo(BigInteger.ZERO) < 0);
        }

        System.out.println("d: " + d + "\n");

        BigInteger M = stringToInt(plainTextMessage);

        System.out.println("The public key can be used to encrypt plaintext "
                + "message: \n\n\"" + plainTextMessage + "\"\n\nrepresented as "
                + "integer M:\n\n" + M + "\n\nproducing ciphertext C such "
                + "that C = M^e mod n:\n");

        BigInteger C = M.modPow(e, n);

        System.out.println("C: " + C + "\n");

        System.out.println("Decryption of C is simply C^d mod n. The decrypted "
                + "ciphertext is:");

        BigInteger decryptedC = C.modPow(d, n);

        System.out.println("\n" + decryptedC + "\n\nwhich matches the "
                + "original plaintext message\n\n" + M + "\n\nand maps back "
                + "into plaintext as\n");

        System.out.print("\"" + intToString(decryptedC) + "\"\n");
    }

    /**
     * Compute the multiplicative inverse of a mod b. If none exists, return 0.
     *
     * @param a the integer to compute the multiplicative inverse of mod b.
     * @param b the modulus used to compute the multiplicative inverse of a.
     * @return the multiplicative inverse of a mod b, or 0 if non exists.
     */
    private static BigInteger modMultInv(BigInteger a, BigInteger b) {

        /**
         * No negative integers.
         */
        if (a.compareTo(BigInteger.ZERO) <= 0
                || b.compareTo(BigInteger.ZERO) <= 0) {

            return BigInteger.ZERO;
        }
        
        /**
         * Use the extended Euclidean algorithm to find the multiplicative
         * inverse of a mod b.
         */
        BigInteger x2 = BigInteger.ONE,
                y2 = BigInteger.ZERO,
                x1 = BigInteger.ZERO,
                y1 = BigInteger.ONE,
                x, y, q, r;

        while (b.compareTo(BigInteger.ZERO) > 0) {

            q = a.divide(b);

            r = a.mod(b);

            a = b;

            b = r;

            x = (x2.subtract(q.multiply(x1)));
            x2 = x1;
            x1 = x;

            y = (y2.subtract(q.multiply(y1)));
            y2 = y1;
            y1 = y;
        }

        return x2;
    }

    /**
     * Creates an integer representation of an ASCII String.
     *
     * @param s the String to be represented with an integer.
     * @return an integer representation of the String.
     */
    public static BigInteger stringToInt(String s) {

        /**
         * Build a hex String from the bytes of s
         * 
         * "Test" = "54657374" = "54"+"65"+"73"+"74" because in hexadecimal:
         * 
         * 'T' = 54
         * 'e' = 65
         * 's' = 73
         * 't' = 74
         */
        
        StringBuilder h = new StringBuilder();

        for (byte b : s.getBytes()) {

            h.append(Integer.toHexString(b));
        }
        
        return new BigInteger(h.toString(), 16);
    }

    /**
     * Reverses the integer result of stringToInt back into an ASCII String.
     *
     * @param i the integer to transform into an ASCII String
     * @return the String
     */
    public static String intToString(BigInteger i) {

        String s = i.toString(16);

        byte[] bytes = new byte[s.length() >> 1];

        for (int x = 0, y = 0; x < s.length(); x += 2, ++y) {

            bytes[y] = new BigInteger(s.substring(x, x + 2), 16).byteValue();
        }

        return new String(bytes);
    }
}
