package com.auth.auth.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenerateKeyUtil {

    private final KeyPair keyPair;

    public GenerateKeyUtil() throws NoSuchAlgorithmException {
        this.keyPair = generateKeyPair();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public static String generateBase64PrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static String generateBase64PublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String generatePemFromPrivateKey(PrivateKey privateKey) {
        return convertToPem("PRIVATE KEY", privateKey.getEncoded());
    }

    public static String generatePemFromPublicKey(PublicKey publicKey) {
        return convertToPem("PUBLIC KEY", publicKey.getEncoded());
    }

    public static void writeToFile(String filename, String content) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(content);
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String convertToPem(String type, byte[] encodedKey) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encodedKey);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }
}
