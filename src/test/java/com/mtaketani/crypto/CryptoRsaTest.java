package com.mtaketani.crypto;

import org.junit.jupiter.api.Test;

import com.mtaketani.crypto.exception.CryptoException;

import static org.junit.jupiter.api.Assertions.*;

class CryptRsaTest {
    @Test
    void 公開鍵で暗号化ー秘密鍵復号化で元に戻るかのテスト() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText = CryptoRsa.encryptoByPublic("test", keyPairRsa.getPublicKey());
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

    @Test
    void 秘密鍵で複数回暗号化しても同一かのテスト() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText1 = CryptoRsa.encryptoByPrivate("test", keyPairRsa.getPrivateKey());
        String encryptoText2 = CryptoRsa.encryptoByPrivate("test", keyPairRsa.getPrivateKey());
        assertEquals(encryptoText1, encryptoText2);
    }

    @Test
    void 秘密鍵で暗号化ー秘密鍵復号化でException発生() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText = CryptoRsa.encryptoByPrivate("test", keyPairRsa.getPrivateKey());
        assertThrows(CryptoException.class
            , () -> CryptoRsa.decryptoByPrivate(encryptoText, keyPairRsa.getPrivateKey()));
    }

    @Test
    void 公開鍵で暗号化ー公開鍵復号化でException発生() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        String encryptoText = CryptoRsa.encryptoByPublic("test", keyPairRsa.getPublicKey());
        assertThrows(CryptoException.class
            , () -> CryptoRsa.decryptoByPublic(encryptoText, keyPairRsa.getPublicKey()));
    }


    @Test
    void 引数Nullテスト_秘密鍵() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        // 秘密鍵の暗号化のテスト
        Throwable exceptionEncryptoByPrivate = assertThrows(NullPointerException.class
            , () -> CryptoRsa.encryptoByPrivate(null, keyPairRsa.getPrivateKey()));
        assertEquals("textはnullを指定できませません。", exceptionEncryptoByPrivate.getMessage());
        exceptionEncryptoByPrivate = assertThrows(NullPointerException.class
            , () -> CryptoRsa.encryptoByPrivate("test", null));
        assertEquals("keyはnullを指定できませません。", exceptionEncryptoByPrivate.getMessage());
        
        // 秘密鍵の復号かのテスト
        Throwable exceptionDecryptoByPrivate = assertThrows(NullPointerException.class
            , () -> CryptoRsa.decryptoByPrivate(null, keyPairRsa.getPrivateKey()));
        assertEquals("encryptoTextはnullを指定できませません。", exceptionDecryptoByPrivate.getMessage());
        exceptionDecryptoByPrivate = assertThrows(NullPointerException.class
            , () -> CryptoRsa.decryptoByPrivate("test", null));
        assertEquals("keyはnullを指定できませません。", exceptionDecryptoByPrivate.getMessage());
    
    }

    @Test
    void 引数Nullテスト_公開鍵() {

        KeyPairRsa keyPairRsa = CryptoRsa.createKeyPair();

        // 公開鍵の暗号化のテスト
        Throwable exceptionEncryptoByPublic = assertThrows(NullPointerException.class
            , () -> CryptoRsa.encryptoByPublic(null, keyPairRsa.getPublicKey()));
        assertEquals("textはnullを指定できませません。", exceptionEncryptoByPublic.getMessage());
        exceptionEncryptoByPublic = assertThrows(NullPointerException.class
            , () -> CryptoRsa.encryptoByPublic("test", null));
        assertEquals("keyはnullを指定できませません。", exceptionEncryptoByPublic.getMessage());
        
        // 公開鍵の復号かのテスト
        Throwable exceptionDecryptoByPublic = assertThrows(NullPointerException.class
            , () -> CryptoRsa.decryptoByPrivate(null, keyPairRsa.getPrivateKey()));
        assertEquals("encryptoTextはnullを指定できませません。", exceptionDecryptoByPublic.getMessage());
        exceptionDecryptoByPublic = assertThrows(NullPointerException.class
            , () -> CryptoRsa.decryptoByPublic("test", null));
        assertEquals("keyはnullを指定できませません。", exceptionDecryptoByPublic.getMessage());
    
    }
}
