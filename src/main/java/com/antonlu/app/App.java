package com.antonlu.app;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import java.util.Base64;
// import javax.crypto.;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception
    {
        System.out.print("Enter master password: ");
        String password = System.console().readLine();

        System.out.println( "Password entered: " + password );

        byte[] hash = Encrypter.hash(password);
        System.out.println( "Hashed master password in hex: " + Encrypter.toHex(hash) );

        String aesKey = Encrypter.generateAESKey();
        System.out.println( "Internal encryption key: " + aesKey);

        // System.out.println( "Hello World!" );
    }
}
