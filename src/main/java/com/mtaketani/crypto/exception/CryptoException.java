package com.mtaketani.crypto.exception;

public class CryptoException extends RuntimeException {
  public CryptoException() { }
  public CryptoException(String message) { super(message); }
  public CryptoException(Throwable cause) { super(cause); }
  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
