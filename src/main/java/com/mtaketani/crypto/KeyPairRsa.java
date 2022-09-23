package com.mtaketani.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyPairRsa {
  private PublicKey publicKey;
  private PrivateKey privateKey;
  public PublicKey getPublicKey() {
    return publicKey;
  }
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }
  public PrivateKey getPrivateKey() {
    return privateKey;
  }
  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  
}
