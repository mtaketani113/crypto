package com.mtaketani.crypto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CryptRsaTest {
    @Test
    void 公開鍵で暗号化ー秘密鍵復号化で元に戻るかのテスト() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText = CryptoRsa.encryptoByPbulic("test", keyPairRsa.getPublicKey());
        String decryptoText = CryptoRsa.decryptoByPrivate(encryptoText, keyPairRsa.getPrivateKey());
        assertEquals("test", decryptoText);
    }

    @Test
    void 秘密鍵で暗号化ー公開鍵復号化で元に戻るかのテスト() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText = CryptoRsa.encryptoByPrivate("test", keyPairRsa.getPrivateKey());
        String decryptoText = CryptoRsa.decryptoByPublic(encryptoText, keyPairRsa.getPublicKey());
        assertEquals("test", decryptoText);
    }
}
