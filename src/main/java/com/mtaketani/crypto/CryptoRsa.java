package com.mtaketani.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import com.mtaketani.crypto.exception.CryptoException;

public class CryptoRsa {

  private static final String NULL_MESSAGE = "はnullを指定できません。";

  /**
   * <p>キーペア作成</p>
   * 作成失敗した場合は、{@code CryptoException}をthrow。
   * 
   * @return 暗号化文字列
   */
  public static KeyPairRsa createKeyPair() {
    // 公開鍵・秘密鍵を生成する。
    KeyPairGenerator kg;
    try {
      kg = KeyPairGenerator.getInstance("RSA");
      kg.initialize(1024);
      KeyPair keyPair = kg.generateKeyPair();
      KeyFactory factoty = KeyFactory.getInstance("RSA");
      RSAPublicKeySpec publicKeySpec = factoty.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
      RSAPrivateKeySpec privateKeySpec = factoty.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
      PublicKey publicKey = factoty.generatePublic(publicKeySpec);
      PrivateKey privateKey = factoty.generatePrivate(privateKeySpec);
      KeyPairRsa keyPairRsa = KeyPairRsa.builder()
        .privateKey(privateKey)
        .publicKey(publicKey).build();
      return keyPairRsa;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * <p>公開鍵で暗号化</p>
   * 暗号化に失敗した場合は、{@code CryptoException}をthrow。
   *
   * @param text 暗号化する文字列
   * @param text 公開鍵
   * @return 暗号化文字列
   */
  public static String encryptoByPublic(String text, PublicKey key) {
    Objects.requireNonNull(text, "text" + NULL_MESSAGE);
    Objects.requireNonNull(key, "key" + NULL_MESSAGE);
    try {
      Cipher encrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encrypter.init(Cipher.ENCRYPT_MODE, key);
      byte[] encrypted = encrypter.doFinal(text.getBytes());
      return  Base64.encodeBase64String(encrypted);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
      | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * <p>秘密鍵で暗号化</p>
   * 暗号化に失敗した場合は、{@code CryptoException}をthrow。
   * 
   * @param text 暗号化する文字列
   * @param key 秘密鍵
   * @return 暗号化文字列
   */
  public static String encryptoByPrivate(String text, PrivateKey key) {
    Objects.requireNonNull(text, "text" + NULL_MESSAGE);
    Objects.requireNonNull(key, "key" + NULL_MESSAGE);
    try {
      Cipher encrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      encrypter.init(Cipher.ENCRYPT_MODE, key);
      byte[] encrypted = encrypter.doFinal(text.getBytes());
      return  Base64.encodeBase64String(encrypted);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
      | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * <p>公開鍵で復号化</p>
   * 復号化に失敗した場合は、{@code CryptoException}をthrow。
   *
   * @param encryptText 復号化する文字列
   * @param text 公開鍵
   * @return 復号化文字列
   */
  public static String decryptoByPublic(String encryptoText, PublicKey key) {
    Objects.requireNonNull(encryptoText, "encryptoText" + NULL_MESSAGE);
    Objects.requireNonNull(key, "key" + NULL_MESSAGE);
    try {
      Cipher dencrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      dencrypter.init(Cipher.DECRYPT_MODE, key);
      byte[] dencrypted = dencrypter.doFinal(Base64.decodeBase64(encryptoText));
      return  new String(dencrypted, "UTF-8");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
      | InvalidKeyException | IllegalBlockSizeException
      | BadPaddingException | UnsupportedEncodingException e) {
      throw new CryptoException(e);
    }
  }

    /**
   * <p>秘密鍵で復号化</p>
   * 復号化に失敗した場合は、{@code CryptoException}をthrow。
   *
   * @param encryptText 復号化する文字列
   * @param text 秘密鍵
   * @return 復号化文字列
   */
  public static String decryptoByPrivate(String encryptoText, PrivateKey key) {
    Objects.requireNonNull(encryptoText, "encryptoText" + NULL_MESSAGE);
    Objects.requireNonNull(key, "key" + NULL_MESSAGE);
    try {
      Cipher dencrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      dencrypter.init(Cipher.DECRYPT_MODE, key);
      byte[] dencrypted = dencrypter.doFinal(Base64.decodeBase64(encryptoText));
      return  new String(dencrypted, "UTF-8");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
      | InvalidKeyException | IllegalBlockSizeException
      | BadPaddingException | UnsupportedEncodingException e) {
      throw new CryptoException(e);
    }
  }
}
