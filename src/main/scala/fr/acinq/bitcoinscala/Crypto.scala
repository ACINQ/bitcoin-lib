package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.KotlinUtils._
import fr.acinq.bitcoin
import fr.acinq.secp256k1.Secp256k1
import scodec.bits.ByteVector

object Crypto {
  /**
   * Secp256k1 private key, which a 32 bytes value
   * We assume that private keys are compressed i.e. that the corresponding public key is compressed
   *
   * @param value value to initialize this key with
   */
  case class PrivateKey(val priv: bitcoin.PrivateKey) {
    val value: ByteVector32 = priv.value

    def add(that: PrivateKey): PrivateKey = PrivateKey(this.priv plus that.priv)

    def subtract(that: PrivateKey): PrivateKey = PrivateKey(this.priv minus that.priv)

    def multiply(that: PrivateKey): PrivateKey = PrivateKey(this.priv times that.priv)

    def +(that: PrivateKey): PrivateKey = add(that)

    def -(that: PrivateKey): PrivateKey = subtract(that)

    def *(that: PrivateKey): PrivateKey = multiply(that)

    def isZero: Boolean = priv.value == bitcoin.ByteVector32.Zeroes

    def publicKey: PublicKey = PublicKey(priv.publicKey())

    /**
     *
     * @param prefix Private key prefix
     * @return the private key in Base58 (WIF) compressed format
     */
    def toBase58(prefix: Byte) = priv.toBase58(prefix)
  }

  object PrivateKey {
    def apply(data: ByteVector): PrivateKey = new PrivateKey(new bitcoin.PrivateKey(data.toArray.take(32)))

    /**
     *
     * @param data serialized private key in bitcoin format
     * @return the de-serialized key
     */
    def fromBin(data: ByteVector): (PrivateKey, Boolean) = {
      val compressed = data.length match {
        case 32 => false
        case 33 if data.last == 1.toByte => true
      }
      (PrivateKey(data.take(32)), compressed)
    }

    def fromBase58(value: String, prefix: Byte): (PrivateKey, Boolean) = {
      val p = bitcoin.PrivateKey.fromBase58(value, prefix)
      (p.getFirst, p.getSecond)
    }
  }

  /**
   * Secp256k1 Public key
   * We assume that public keys are always compressed
   *
   * @param value serialized public key, in compressed format (33 bytes)
   */
  case class PublicKey(pub: bitcoin.PublicKey) {
    val value: ByteVector = pub.value

    def hash160: ByteVector = ByteVector.view(pub.hash160())

    def isValid: Boolean = isPubKeyValidStrict(this.value)

    def add(that: PublicKey): PublicKey = PublicKey(this.pub plus that.pub)

    def add(that: PrivateKey): PublicKey = PublicKey(this.pub plus that.priv.publicKey())

    def subtract(that: PublicKey): PublicKey = PublicKey(this.pub plus that.pub)

    def multiply(that: PrivateKey): PublicKey = PublicKey(this.pub times that.priv)

    def +(that: PublicKey): PublicKey = add(that)

    def -(that: PublicKey): PublicKey = subtract(that)

    def *(that: PrivateKey): PublicKey = multiply(that)

    def toUncompressedBin: ByteVector = ByteVector.view(pub.toUncompressedBin)

    override def toString = pub.toString
  }


  object PublicKey {
    /**
     * @param raw        serialized value of this public key (a point)
     * @param checkValid indicates whether or not we check that this is a valid public key; this should be used
     *                   carefully for optimization purposes
     * @return
     */
    def apply(raw: ByteVector, checkValid: Boolean = true): PublicKey = fromBin(raw, checkValid)

    def fromBin(input: ByteVector, checkValid: Boolean = true): PublicKey = {
      require(isPubKeyValidLax(input))
      if (checkValid) {
        Secp256k1.get().pubkeyParse(input.toArray)
      }
      PublicKey(new bitcoin.PublicKey(bitcoin.PublicKey.compress(input.toArray)))
    }
  }


  /**
   * Computes ecdh using secp256k1's variant: sha256(priv * pub serialized in compressed format)
   *
   * @param priv private value
   * @param pub  public value
   * @return ecdh(priv, pub) as computed by libsecp256k1
   */
  def ecdh(priv: PrivateKey, pub: PublicKey): ByteVector32 = ByteVector32(ByteVector.view(bitcoin.Crypto.ecdh(priv.priv, pub.pub)))

  def hmac512(key: ByteVector, data: ByteVector): ByteVector = ByteVector.view(bitcoin.Crypto.hmac512(key.toArray, data.toArray))

  def sha256 = (x: ByteVector) => ByteVector32(ByteVector.view(bitcoin.Crypto.sha256(x)))

  def ripemd160 = (x: ByteVector) => ByteVector.view(bitcoin.Crypto.ripemd160(x))

  /**
   * 160 bits bitcoin hash, used mostly for address encoding
   * hash160(input) = RIPEMD160(SHA256(input))
   *
   * @param input array of byte
   * @return the 160 bits BTC hash of input
   */
  def hash160(input: ByteVector): ByteVector = ByteVector.view(bitcoin.Crypto.hash160(input.toArray))

  /**
   * 256 bits bitcoin hash
   * hash256(input) = SHA256(SHA256(input))
   *
   * @param input array of byte
   * @return the 256 bits BTC hash of input
   */
  def hash256(input: ByteVector): ByteVector32 = ByteVector32(ByteVector.view(bitcoin.Crypto.hash256(input.toArray)))

  def isDERSignature(sig: ByteVector): Boolean = bitcoin.Crypto.isDERSignature(sig.toArray)

  def isLowDERSignature(sig: ByteVector): Boolean = bitcoin.Crypto.isLowDERSignature(sig.toArray)

  def checkSignatureEncoding(sig: ByteVector, flags: Int): Boolean = bitcoin.Crypto.checkSignatureEncoding(sig.toArray, flags)

  def checkPubKeyEncoding(key: ByteVector, flags: Int, sigVersion: Int): Boolean = bitcoin.Crypto.checkPubKeyEncoding(key.toArray, flags, sigVersion)

  /**
   *
   * @param key serialized public key
   * @return true if the key is valid. Please not that this performs very basic tests and does not check that the
   *         point represented by this key is actually valid.
   */
  def isPubKeyValidLax(key: ByteVector): Boolean = key.length match {
    case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  /**
   *
   * @param key serialized public key
   * @return true if the key is valid. This check is much more expensive than its lax version since here we check that
   *         the public key is a valid point on the secp256k1 curve
   */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) && bitcoin.Crypto.isPubKeyValid(key.toArray)

  def isPubKeyCompressedOrUncompressed(key: ByteVector): Boolean = key.length match {
    case 65 if key(0) == 4 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isPubKeyCompressed(key: ByteVector): Boolean = key.length match {
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isDefinedHashtypeSignature(sig: ByteVector): Boolean = bitcoin.Crypto.isDefinedHashTypeSignature(sig.toArray)

  def compact2der(signature: ByteVector64): ByteVector = bitcoin.Crypto.compact2der(signature)

  def der2compact(signature: ByteVector): ByteVector64 = bitcoin.Crypto.der2compact(signature.toArray)

  /**
   * @param data      data
   * @param signature signature
   * @param publicKey public key
   * @return true is signature is valid for this data with this public key
   */
  def verifySignature(data: ByteVector, signature: ByteVector64, publicKey: PublicKey): Boolean = bitcoin.Crypto.verifySignature(data.toArray, signature, publicKey.pub)

  /**
   *
   * @param privateKey private key
   * @return the corresponding public key
   */
  def publicKeyFromPrivateKey(privateKey: ByteVector) = PrivateKey(privateKey).publicKey

  /**
   * Sign data with a private key, using RCF6979 deterministic signatures
   *
   * @param data       data to sign
   * @param privateKey private key. If you are using bitcoin "compressed" private keys make sure to only use the first 32 bytes of
   *                   the key (there is an extra "1" appended to the key)
   * @return a signature in compact format (64 bytes)
   */
  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 = bitcoin.Crypto.sign(data, privateKey.priv)

  def sign(data: ByteVector, privateKey: PrivateKey): ByteVector64 = sign(data.toArray, privateKey)

  /**
   * Recover public keys from a signature and the message that was signed. This method will return 2 public keys, and the signature
   * can be verified with both, but only one of them matches that private key that was used to generate the signature.
   *
   * @param signature signature
   * @param message   message that was signed
   * @return a recovered public key
   */
  def recoverPublicKey(signature: ByteVector64, message: ByteVector, recoveryId: Int): PublicKey = PublicKey(bitcoin.Crypto.recoverPublicKey(signature, message.toArray, recoveryId))

  def recoverPublicKey(signature: ByteVector64, message: ByteVector): (PublicKey, PublicKey) = {
    val p = bitcoin.Crypto.recoverPublicKey(signature, message.toArray)
    (PublicKey(p.getFirst), PublicKey(p.getSecond))
  }
}
