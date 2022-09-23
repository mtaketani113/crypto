package com.mtaketani.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class KeyPairRsa {
  private PublicKey publicKey;
  private PrivateKey privateKey;
}
