package com.mtaketani.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ObjectUtils;

public class CryptoAes {

  private static final String ENCRYPT_KEY =
      ObjectUtils.defaultIfNull(System.getenv("crypto.aes.key"), "1234567890123456");
  private static final String ENCRYPT_IV =
      ObjectUtils.defaultIfNull(System.getenv("crypto.aes.iv"), "6543210987654321");

  /**
   * <p>暗号化メソッド。</p>
   * 暗号化に失敗した場合は、{@code null}を返却。
   *
   * @param text 暗号化する文字列
   * @return 暗号化文字列
   */
  public static String encrypto(String text) {

    try {
      // 暗号化キーと初期化ベクトルをバイト配列へ変換
      byte[] byteKey = ENCRYPT_KEY.getBytes("UTF-8");
      byte[] byteIv = ENCRYPT_IV.getBytes("UTF-8");

      // 暗号化キーと初期化ベクトルのオブジェクト生成
      SecretKeySpec key = new SecretKeySpec(byteKey, "AES");
      GCMParameterSpec iv = new GCMParameterSpec(128, byteIv);

      // Cipherオブジェクト生成
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

      // Cipherオブジェクトの初期化
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      // 暗号化の結果取得
      byte[] byteResult = cipher.doFinal(text.getBytes("UTF-8"));

      // Base64へエンコードして暗号化文字列を返却
      return Base64.encodeBase64String(byteResult);

    } catch (Exception e) {
      e.printStackTrace();
    }
    // null
    return null;
  }

  /**
   * <p>復号化メソッド</p>
   * 復号化に失敗した場合は、{@code null}を返却。
   *
   * @param encryptText 復号化する文字列
   * @return 復号化文字列
   */
  public static String decrypto(String encryptText) {

    try {
      // 暗号化キーと初期化ベクトルをバイト配列へ変換
      byte[] byteKey = ENCRYPT_KEY.getBytes("UTF-8");
      byte[] byteIv = ENCRYPT_IV.getBytes("UTF-8");

      // 復号化キーと初期化ベクトルのオブジェクト生成
      SecretKeySpec key = new SecretKeySpec(byteKey, "AES");
      GCMParameterSpec iv = new GCMParameterSpec(128, byteIv);

      // Cipherオブジェクト生成
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

      // Cipherオブジェクトの初期化
      cipher.init(Cipher.DECRYPT_MODE, key, iv);

      // 復号化の結果取得
      byte[] byteResult = cipher.doFinal(Base64.decodeBase64(encryptText));

      // バイト配列を文字列へ変換して復号化文字列を返却
      return new String(byteResult, "UTF-8");

    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
