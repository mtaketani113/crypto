package com.mtaketani.crypto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CryptHashTest {
    @Test
    void 違う値を暗号化した場合は違う値() {
        String encryptoText1 = CryptoHash.cryptoSha256("test1");
        String encryptoText2 = CryptoHash.cryptoSha256("test2");
        assertNotEquals(encryptoText1, encryptoText2);
    }
    @Test
    void 同じ値を暗号化した場合は同じ値() {
        String encrypto1 = CryptoHash.cryptoSha256("test");
        String encrypto2 = CryptoHash.cryptoSha256("test");
        assertEquals(encrypto1, encrypto2);
    }
    @Test
    void 引数Nullテスト() {
        Throwable exceptionEncrypto = assertThrows(NullPointerException.class
            , () -> CryptoHash.cryptoSha256(null));
        assertEquals("textはnullを指定できませません。", exceptionEncrypto.getMessage());
    }
}
