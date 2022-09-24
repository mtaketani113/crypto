package com.mtaketani.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ObjectUtils;

import com.mtaketani.crypto.exception.CryptoException;

public class CryptoAes {

  private static final String ENCRYPT_KEY =
      ObjectUtils.defaultIfNull(System.getenv("crypto.aes.key"), "1234567890123456");
  private static final String ENCRYPT_IV =
      ObjectUtils.defaultIfNull(System.getenv("crypto.aes.iv"), "6543210987654321");

  /**
   * <p>暗号化メソッド。</p>
   * 暗号化に失敗した場合は、{@code CryptoException}をthrow。
   *
   * @param text 暗号化する文字列
   * @return 暗号化文字列
   */
  public static String encrypto(String text) {
    Objects.requireNonNull(text, "textはnullを指定できませません。");

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

    } catch (UnsupportedEncodingException | NoSuchAlgorithmException
      | NoSuchPaddingException | IllegalBlockSizeException
      | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * <p>復号化メソッド</p>
   * 復号化に失敗した場合は、{@code CryptoException}をthrow。
   *
   * @param encryptText 復号化する文字列
   * @return 復号化文字列
   */
  public static String decrypto(String encryptoText) {
    Objects.requireNonNull(encryptoText, "encryptoTextはnullを指定できませません。");

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
      byte[] byteResult = cipher.doFinal(Base64.decodeBase64(encryptoText));

      // バイト配列を文字列へ変換して復号化文字列を返却
      return new String(byteResult, "UTF-8");

    } catch (UnsupportedEncodingException | IllegalBlockSizeException
      | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
      | NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoException(e);
    }
  }
}
