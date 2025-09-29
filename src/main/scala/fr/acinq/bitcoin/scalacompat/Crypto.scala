package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.KotlinUtils._
import scodec.bits.ByteVector

object Crypto {

  // @formatter:off
  /** Specify how private keys are tweaked when creating Schnorr signatures. */
  sealed trait SchnorrTweak
  object SchnorrTweak {
    /** The private key is directly used, without any tweaks. */
    case object NoTweak extends SchnorrTweak
  }

  sealed trait TaprootTweak extends SchnorrTweak
  object TaprootTweak {
    /** The private key is tweaked with H_TapTweak(public key) (this is used for key path spending when there is no script tree). */
    case object NoScriptTweak extends TaprootTweak
    /** The private key is tweaked with H_TapTweak(public key || merkle_root) (this is used for key path spending when a script tree exists). */
    case class ScriptTweak(merkleRoot: ByteVector32) extends TaprootTweak
    object ScriptTweak {
      def apply(scriptTree: ScriptTree): ScriptTweak = ScriptTweak(scriptTree.hash())
    }
  }
  // @formatter:on

  /**
   * A bitcoin private key.
   * A private key is valid if it is not 0 and less than the secp256k1 curve order when interpreted as an integer (most significant byte first).
   * The probability of choosing a 32-byte string uniformly at random which is an invalid private key is negligible, so this condition is not checked by default.
   * However, if you receive a private key from an external, untrusted source, you should call `isValid()` before actually using it.
   */
  case class PrivateKey(priv: bitcoin.PrivateKey) {
    val value: ByteVector32 = priv.value

    def add(that: PrivateKey): PrivateKey = PrivateKey(this.priv plus that.priv)

    def subtract(that: PrivateKey): PrivateKey = PrivateKey(this.priv minus that.priv)

    def multiply(that: PrivateKey): PrivateKey = PrivateKey(this.priv times that.priv)

    def +(that: PrivateKey): PrivateKey = add(that)

    def -(that: PrivateKey): PrivateKey = subtract(that)

    def *(that: PrivateKey): PrivateKey = multiply(that)

    def isZero: Boolean = priv.value == bitcoin.ByteVector32.Zeroes

    def isValid: Boolean = priv.isValid

    def publicKey: PublicKey = PublicKey(priv.publicKey())

    def xOnlyPublicKey(): XonlyPublicKey = XonlyPublicKey(publicKey)

    /**
     * @param prefix Private key prefix
     * @return the private key in Base58 (WIF) compressed format
     */
    def toBase58(prefix: Byte): String = priv.toBase58(prefix)

    def toHex: String = priv.toHex

    override def toString: String = priv.toString
  }

  object PrivateKey {
    def apply(data: ByteVector): PrivateKey = PrivateKey(new bitcoin.PrivateKey(data.toArray))

    /**
     * @param data serialized private key in bitcoin format
     * @return the de-serialized key
     */
    def fromBin(data: ByteVector): (PrivateKey, Boolean) = {
      val compressed = data.length match {
        case 32 => false
        case 33 if data.last == 1.toByte => true
      }
      (PrivateKey(data), compressed)
    }

    def fromBase58(value: String, prefix: Byte): (PrivateKey, Boolean) = {
      val p = bitcoin.PrivateKey.fromBase58(value, prefix)
      (p.getFirst, p.getSecond)
    }
  }

  /**
   * A bitcoin public key (in compressed form).
   * A public key is valid if it represents a point on the secp256k1 curve.
   * The validity of this public key is not checked by default, because when you create a public key from a private key it will always be valid.
   * However, if you receive a public key from an external, untrusted source, you should call `isValid()` before actually using it.
   */
  case class PublicKey(pub: bitcoin.PublicKey) {
    val value: ByteVector = pub.value

    def xOnly: XonlyPublicKey = XonlyPublicKey(pub.xOnly())

    def hash160: ByteVector = ByteVector.view(pub.hash160())

    def isValid: Boolean = pub.isValid

    def add(that: PublicKey): PublicKey = PublicKey(this.pub plus that.pub)

    def add(that: PrivateKey): PublicKey = PublicKey(this.pub plus that.priv.publicKey())

    def subtract(that: PublicKey): PublicKey = PublicKey(this.pub minus that.pub)

    def multiply(that: PrivateKey): PublicKey = PublicKey(this.pub times that.priv)

    def +(that: PublicKey): PublicKey = add(that)

    def -(that: PublicKey): PublicKey = subtract(that)

    def *(that: PrivateKey): PublicKey = multiply(that)

    def toUncompressedBin: ByteVector = ByteVector.view(pub.toUncompressedBin)

    def toHex: String = pub.toHex

    override def toString: String = pub.toString
  }

  object PublicKey {
    /**
     * @param raw        serialized value of this public key (a point)
     * @param checkValid indicates whether or not we check that this is a valid public key; this should be used
     *                   carefully for optimization purposes
     */
    def apply(raw: ByteVector, checkValid: Boolean = true): PublicKey = fromBin(raw, checkValid)

    def fromBin(input: ByteVector, checkValid: Boolean = true): PublicKey = {
      require(isPubKeyValidLax(input))
      require(!checkValid || Crypto.isPubKeyValidStrict(input), "public key is invalid")
      PublicKey(new bitcoin.PublicKey(bitcoin.PublicKey.compress(input.toArray)))
    }
  }

  /**
   * x-only pubkey, used with Schnorr signatures (see https://github.com/bitcoin/bips/tree/master/bip-0340)
   * we only store the x coordinate of the pubkey, the y coordinate is always even
   */
  case class XonlyPublicKey(pub: bitcoin.XonlyPublicKey) {
    val publicKey: PublicKey = PublicKey(pub.getPublicKey)

    def tweak(tapTweak: TaprootTweak): ByteVector32 = pub.tweak(scala2kmp(tapTweak))

    /**
     * "tweaks" this key with an optional merkle root
     *
     * @param tapTweak taproot tweak
     * @return an (x-only pubkey, parity) pair
     */
    def outputKey(tapTweak: TaprootTweak): (XonlyPublicKey, Boolean) = {
      val p = pub.outputKey(scala2kmp(tapTweak))
      (XonlyPublicKey(p.getFirst), p.getSecond)
    }

    /** Tweak this key with the merkle root of the given script tree. */
    def outputKey(scriptTree: ScriptTree): (XonlyPublicKey, Boolean) = outputKey(TaprootTweak.ScriptTweak(scriptTree))

    /** Tweak this key with the merkle root provided. */
    def outputKey(merkleRoot: ByteVector32): (XonlyPublicKey, Boolean) = outputKey(TaprootTweak.ScriptTweak(merkleRoot))

    /**
     * add a public key to this x-only key
     *
     * @param that public key
     * @return a (key, parity) pair where `key` is the x-only-pubkey for `this` + `that` and `parity` is true if `this` + `that` is odd
     */
    def add(that: PublicKey): (XonlyPublicKey, Boolean) = {
      val p = pub.plus(that.pub)
      (XonlyPublicKey(p.getFirst), p.getSecond)
    }

    def +(that: PublicKey): (XonlyPublicKey, Boolean) = add(that)
  }

  object XonlyPublicKey {
    def apply(pub: PublicKey) = new XonlyPublicKey(new bitcoin.XonlyPublicKey(pub.pub))
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

  def sha256(x: ByteVector): ByteVector32 = ByteVector32(ByteVector.view(bitcoin.Crypto.sha256(x)))

  def ripemd160(x: ByteVector): ByteVector = ByteVector.view(bitcoin.Crypto.ripemd160(x))

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
   * @param key serialized public key
   * @return true if the key is valid. This check is much more expensive than its lax version since here we check that
   *         the public key is a valid point on the secp256k1 curve
   */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) && bitcoin.Crypto.isPubKeyValid(key.toArray)

  def isPubKeyCompressedOrUncompressed(key: ByteVector): Boolean = bitcoin.Crypto.isPubKeyCompressedOrUncompressed(key.toArray)

  def isPubKeyCompressed(key: ByteVector): Boolean = bitcoin.Crypto.isPubKeyCompressed(key.toArray)

  def isDefinedHashTypeSignature(sig: ByteVector): Boolean = bitcoin.Crypto.isDefinedHashTypeSignature(sig.toArray)

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
   * @param data      data
   * @param signature signature
   * @param publicKey public key
   * @return true is signature is valid for this data with this public key
   */
  def verifySignatureSchnorr(data: ByteVector32, signature: ByteVector64, publicKey: XonlyPublicKey): Boolean = {
    bitcoin.Crypto.verifySignatureSchnorr(data, signature, publicKey.pub)
  }

  /**
   * @param privateKey private key
   * @return the corresponding public key
   */
  def publicKeyFromPrivateKey(privateKey: ByteVector): PublicKey = PrivateKey(privateKey).publicKey

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
   * Compute the Schnorr signature of data with private key
   *
   * @param data       data to sign
   * @param privateKey private key. If you are using bitcoin "compressed" private keys make sure to only use the first 32 bytes of
   *                   the key (there is an extra "1" appended to the key)
   * @return a signature in compact format (64 bytes)
   */
  def signSchnorr(data: ByteVector32, privateKey: PrivateKey, schnorrTweak: SchnorrTweak = SchnorrTweak.NoTweak, auxrand32: Option[ByteVector32] = None): ByteVector64 = {
    bitcoin.Crypto.signSchnorr(data, privateKey, scala2kmp(schnorrTweak), auxrand32.map(scala2kmp).orNull)
  }

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

  def taggedHash(input: Array[Byte], tag: String): ByteVector32 = bitcoin.Crypto.taggedHash(input, tag)
}
