# crypto

以下3点の暗号化を提供する。

- AES暗号
- RSA暗号
- Hash化

##  AES暗号

クラス`CryptoAes`で提供する。
暗号化と、復号化のメソッドを提供。

##  RSA暗号

クラス`CryptoRsa`で提供する

`KeyPairRsa`で秘密鍵と公開鍵を作成する。
それを利用して暗号化、復号化のメソッドを利用できる。

##  Hash化

クラス`CryptoHash`で提供する。
一方向のHash化。暗号化のみ提供する。
