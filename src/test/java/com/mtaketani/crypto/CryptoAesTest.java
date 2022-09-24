package com.mtaketani.crypto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CryptAesTest {
    @Test
    void 暗号化復号化で元に戻るかのテスト() {
        String encryptoText = CryptoAes.encrypto("test");
        String decryptoText = CryptoAes.decrypto(encryptoText);
        assertEquals("test", decryptoText);
    }

    @Test
    void 引数Nullテスト() {
        Throwable exceptionEncrypto = assertThrows(NullPointerException.class
            , () -> CryptoAes.encrypto(null));
        assertEquals("textはnullを指定できませません。", exceptionEncrypto.getMessage());
        Throwable exceptionDecrypto = assertThrows(NullPointerException.class
            , () -> CryptoAes.decrypto(null));
        assertEquals("encryptoTextはnullを指定できませません。", exceptionDecrypto.getMessage());
    }
}
