package com.mtaketani.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ObjectUtils;

import com.mtaketani.crypto.exception.CryptoException;

public class CryptoHash {

  private static final String FIXED_SALT =
      ObjectUtils.defaultIfNull(System.getenv("crypto.hash.salt"), "1234567890123456");

  /**
   * <p>SHA-256の暗号化メソッド。</p>
   * 暗号化に失敗した場合は、{@code CryptoException}を返却。
   *
   * @param text 暗号化する文字列
   * @return 暗号化文字列
   */
  public static String cryptoSha256(String text) {

    // Saltを追加
    String textWithSalt = text + FIXED_SALT;
    // ハッシュ化
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
    byte[] byteResult = digest.digest(textWithSalt.getBytes());

    // Base64へエンコードして暗号化文字列を返却
    return Base64.encodeBase64String(byteResult);
  }
}
