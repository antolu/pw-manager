package com.antonlu.app;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.KeyGenerator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.math.BigInteger;

/**
 * Encrypter
 */
public class Encrypter {
    private final static int ITERATIONS = 1000;

    public static String generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);

        SecretKey aesKey = kgen.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());

        return encodedKey;
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return salt;
    }

    public static byte[] hash(String toHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = getSalt();

        char[] chars = toHash.toCharArray();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hash = skf.generateSecret(spec).getEncoded();

        return hash;
    }

    public static byte[] encrypt(String key, byte[] toEncrypt) {
        return null;
    }

    public static byte[] decrypt(String key, byte[] toDecrypt) {
        return null;
    }

    public static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
}