//Name: David DeCosta
/*
 * Description: This program implements Diffie-Hellman and ElGamal cryptographic algorithms 
 * for secure key exchange and message encryption/decryption using modular arithmetic and primitive 
 * roots of a prime number.
 */

import java.util.Random;

class Main {
    public static final long q = 41;  // prime number
    public static final long primRoot = findPrimitiveRoot(q); // primitive root of q

    public static void main(String[] args) {
        // Question 1 the Diffie
        System.out.println("QUESTIONS 1:");
        long xa = getSecretKey(q); // alice private key
        long xb = getSecretKey(q); // bob private key

        long ya = getPublicKey(xa); // alice public key
        long yb = getPublicKey(xb); // bob pulic key

        long sharedKeyA = theSharedKey(yb, xa); // send bobs public key and alices private key
        long sharedKeyB = theSharedKey(ya, xb); // send alice public key and bob private
        //both these shared keys should be the same

        System.out.println("alice public key: " + ya);
        System.out.println("bob public key: " + yb);
        System.out.println("the shared secret key1: " + sharedKeyA);
        System.out.println("the shared secret key2: " + sharedKeyB);


        //Question 2 the elGamal
        System.out.println("QUESTIONS 2:");
        long alicePrivate = getSecretKey(q); // alic private key
        long alicePublic = getPublicKey(alicePrivate); // alice public key

        // encryption by Bob
        long message = 19; // the msg Bob wants to send
        long[] encryptedMessage = encryptElGamal(message, alicePublic, q); //bob encrypts msg using alices public key.
        long c1 = encryptedMessage[0]; // c1   to be sent to alice  g^k mod q
        long c2 = encryptedMessage[1]; // c2  to be sent to alice   (h^k mod q)

        // decryption by Alice
        long decryptedMessage = decryptElGamal(c1, c2, alicePrivate, q); // alice decrypts the message using her private key and the ciphertext she got
        System.out.println("alice orig msg: " + message);
        System.out.println("alice encrpt msg: " + encryptedMessage);
        System.out.println("alice decrypted msg: " + decryptedMessage);
    
    }

    static long decryptElGamal(long c1, long c2, long xa, long q) {
        long keyShared = raiseThenMod(c1, xa, q); // shared secret = c1^xa mod q
        long keySharedInverse = modInverse(keyShared, q); // modular inverse of shared secret to be used to decrypt c2
        long message = (c2 * keySharedInverse) % q; // message = (c2 * shared secret inverse) mod q
        return message;
    }
    
    static long modInverse(long a, long m) {
        for (long x = 1; x < m; x++) {      //mod inverse of 'a' mod 'm' is the number 'x' that is (a*x) mod m =1
            if ((a * x) % m == 1) {
                return x;
            }
        }
        return -1; //failed
    }
    
    static long[] encryptElGamal(long message, long ya, long q) {
        Random random = new Random();
        long k = (long) (random.nextInt((int) q - 1)); // random integer k
        long c1 = raiseThenMod(primRoot, k, q); // c1 = primroot^k mod q
        long sharedKey = raiseThenMod(ya, k, q); // shared = ya^k mod q
        long c2 = (message * sharedKey) % q; // c2 = (m * shared secret) mod q
        return new long[]{c1, c2};
    }
    


    static long findPrimitiveRoot(long p) {
        long candidate = 2; // start with 2
        while (candidate < p) { // keep checking until find a prim root
            if (isPrimitiveRoot(candidate, p)) { 
                System.out.println("FOUND PRIM ROOT: " + candidate);
                return candidate;
            }
          //  System.out.println("moving to next, i checked  " + candidate);
            candidate++; // check the next number
        }
        return -1; // if no primitive root is found
    }
    
    static boolean isPrimitiveRoot(long candidate, long p) {
        long z = p - 1;   // this is the euler tot function
        for (long i = 1; i < z; i++) {  // check all values from 1 to z
            if (raiseThenMod(candidate, i, p) == 1) { // this checks if candidate^i % p == 1 because it should not be 1
              //  System.out.println("not prim root: " + candidate + "^" + i + " % " + p + " = 1");
                return false; 
            }
        }
        return true; // if no value is 1, then it is a primitive root
    }

    // helps deal with large numbers by using mod arithmetic
    static long raiseThenMod(long base, long exponent, long mod) {
        long result = 1;  // start with 1 because anything raised to 0 is 1
        base = base % mod;  //make sure stay in range
    
        while (exponent > 0) { //once exponent is 0, done because mult by all pows of 2
            if (exponent % 2 == 1) {  // if odd then multiply by base
                result = (result * base) % mod; //  represents the current power of 2
            }

            exponent = exponent / 2;
            base = (base * base) % mod; // move to next power of 2
        }
    
        // result is base^exponent % mod.
       // System.out.println("Result: " + result);
        return result;
    }

    static long getSecretKey(long q) {
        Random random = new Random();
        return (long) (random.nextInt((int) q - 1)); //has to be less than q
    }

    static long getPublicKey(long secretKey) {
        return raiseThenMod(primRoot, secretKey, q); // primRoot^secretKey % q
    }

    // use secret key from one person and public key from the other and youll get the same key
    static long theSharedKey(long publicKey, long secretKey) {
        return raiseThenMod(publicKey, secretKey, q); // publicKey^secretKey % q
    }


}