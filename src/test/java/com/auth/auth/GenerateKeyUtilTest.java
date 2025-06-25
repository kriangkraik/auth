package com.auth.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.auth.auth.utils.GenerateKeyUtil;

class GenerateKeyUtilTest {
    private GenerateKeyUtil keyUtil;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        keyUtil = new GenerateKeyUtil();
        privateKey = keyUtil.getPrivateKey();
        publicKey = keyUtil.getPublicKey();
    }

    @Test
    void testKeyPairIsNotNull() {
        assertNotNull(privateKey, "Private key should not be null");
        assertNotNull(publicKey, "Public key should not be null");
    }

    @Test
    void testBase64PrivateKeyGeneration() {
        String base64Private = GenerateKeyUtil.generateBase64PrivateKey(privateKey);
        assertNotNull(base64Private);
        assertFalse(base64Private.isEmpty());
    }

    @Test
    void testBase64PublicKeyGeneration() {
        String base64Public = GenerateKeyUtil.generateBase64PublicKey(publicKey);
        assertNotNull(base64Public);
        assertFalse(base64Public.isEmpty());
    }

    @Test
    void testPemPrivateKeyFormat() {
        String pemPrivate = GenerateKeyUtil.generatePemFromPrivateKey(privateKey);
        assertTrue(pemPrivate.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(pemPrivate.endsWith("-----END PRIVATE KEY-----"));
    }

    @Test
    void testPemPublicKeyFormat() {
        String pemPublic = GenerateKeyUtil.generatePemFromPublicKey(publicKey);
        assertTrue(pemPublic.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(pemPublic.endsWith("-----END PUBLIC KEY-----"));
    }

    @Test
    void testWriteToFile() throws IOException {
        String pemPublic = GenerateKeyUtil.generatePemFromPublicKey(publicKey);
        String content = pemPublic;
        String filename = "test_key_file.pem";
        GenerateKeyUtil.writeToFile(filename, content);

        File file = new File(filename);
        assertTrue(file.exists());

        String fileContent = Files.readString(file.toPath());
        assertEquals(content, fileContent);

        // cleanup File.
        Files.deleteIfExists(file.toPath());
    }

}
