package fr.acinq.bitcoinscala

import fr.acinq.bitcoin
import fr.acinq.bitcoinscala.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoinscala.KotlinUtils._
import fr.acinq.bitcoinscala.Protocol._
import scodec.bits.ByteVector

import java.io.OutputStream
import java.nio.ByteOrder
import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
object DeterministicWallet {

  case class KeyPath(keyPath: bitcoin.KeyPath) {
    val path: Seq[Long] = keyPath.path.asScala.toList.map(_.longValue())

    def lastChildNumber: Long = keyPath.getLastChildNumber

    def derive(number: Long): KeyPath = KeyPath(keyPath.derive(number))

    override def toString = keyPath.toString
  }

  object KeyPath {
    val Root = KeyPath(new bitcoin.KeyPath(""))

    def apply(path: Seq[Long]): KeyPath = new KeyPath(new bitcoin.KeyPath(path.map(x => Long.box(x)).toList.asJava))

    /**
     *
     * @param path key path. A list of integers separated by a `/`. May start with "/" or "m/". A single quote appended
     *             at the end means use the hardened version of the ley index (example: m/44'/0'/0'/0)
     * @return a KeyPath instance
     */
    def apply(path: String): KeyPath = KeyPath(new bitcoin.KeyPath(path))

    def childNumberToString(childNumber: Long) = if (isHardened(childNumber)) (childNumber - hardenedKeyIndex).toString + "'" else childNumber.toString
  }

  val hardenedKeyIndex = 0x80000000L

  def hardened(index: Long): Long = hardenedKeyIndex + index

  def isHardened(index: Long): Boolean = index >= hardenedKeyIndex

  case class ExtendedPrivateKey(priv: bitcoin.DeterministicWallet.ExtendedPrivateKey) {
    val secretkeybytes: ByteVector32 = priv.secretkeybytes
    val chaincode: ByteVector32 = priv.chaincode
    val depth: Int = priv.depth
    val path: KeyPath = KeyPath(priv.path)
    val parent: Long = priv.parent

    def privateKey: PrivateKey = priv.privateKey

    def publicKey: PublicKey = privateKey.publicKey

    override def toString = priv.toString
  }

  object ExtendedPrivateKey {
    def apply(secretkeybytes: ByteVector32, chaincode: ByteVector32, depth: Int, derivationPath: KeyPath, parent: Long) = new ExtendedPrivateKey(
      new bitcoin.DeterministicWallet.ExtendedPrivateKey(secretkeybytes, chaincode, depth, derivationPath.keyPath, parent)
    )

    def decode(input: String, parentPath: KeyPath = KeyPath.Root): (Int, ExtendedPrivateKey) = {
      val p = bitcoin.DeterministicWallet.ExtendedPrivateKey.decode(input, parentPath.keyPath)
      (p.getFirst, ExtendedPrivateKey(p.getSecond))
    }
  }

  def encode(input: ExtendedPrivateKey, prefix: Int): String = bitcoin.DeterministicWallet.encode(input.priv, prefix)

  case class ExtendedPublicKey(pub: bitcoin.DeterministicWallet.ExtendedPublicKey) {
    val publickeybytes: ByteVector = pub.publickeybytes
    val chaincode: ByteVector32 = pub.chaincode
    val depth: Int = pub.depth
    val path: KeyPath = KeyPath(pub.path)
    val parent: Long = pub.parent

    def publicKey: PublicKey = pub.getPublicKey

    override def toString = pub.toString
  }

  object ExtendedPublicKey {
    def apply(publicKey: ByteVector, chaincode: ByteVector32, depth: Int, derivationPath: KeyPath, parent: Long) = new ExtendedPublicKey(
      new bitcoin.DeterministicWallet.ExtendedPublicKey(publicKey, chaincode, depth, derivationPath.keyPath, parent)
    )

    def decode(input: String, parentPath: KeyPath = KeyPath.Root): (Int, ExtendedPublicKey) = {
      val p = bitcoin.DeterministicWallet.ExtendedPublicKey.decode(input, parentPath.keyPath)
      (p.getFirst, ExtendedPublicKey(p.getSecond))
    }
  }

  def encode(input: ExtendedPublicKey, prefix: Int): String = bitcoin.DeterministicWallet.encode(input.pub, prefix)

  def write(input: ExtendedPublicKey, output: OutputStream): Unit = {
    writeUInt8(input.depth, output)
    writeUInt32(input.parent.toInt, output, ByteOrder.BIG_ENDIAN)
    writeUInt32(input.path.lastChildNumber.toInt, output, ByteOrder.BIG_ENDIAN)
    writeBytes(input.chaincode.toArray, output)
    writeBytes(input.publickeybytes.toArray, output)
  }

  /**
   *
   * @param seed random seed
   * @return a "master" private key
   */
  def generate(seed: ByteVector): ExtendedPrivateKey = ExtendedPrivateKey(bitcoin.DeterministicWallet.generate(seed))

  /**
   *
   * @param input extended private key
   * @return the public key for this private key
   */
  def publicKey(input: ExtendedPrivateKey): ExtendedPublicKey = ExtendedPublicKey(bitcoin.DeterministicWallet.publicKey(input.priv))

  /**
   *
   * @param input extended public key
   * @return the fingerprint for this public key
   */
  def fingerprint(input: ExtendedPublicKey): Long = bitcoin.DeterministicWallet.fingerprint(input.pub)

  /**
   *
   * @param input extended private key
   * @return the fingerprint for this private key (which is based on the corresponding public key)
   */
  def fingerprint(input: ExtendedPrivateKey): Long = bitcoin.DeterministicWallet.fingerprint(input.priv)

  /**
   *
   * @param parent extended private key
   * @param index  index of the child key
   * @return the derived private key at the specified index
   */
  def derivePrivateKey(parent: ExtendedPrivateKey, index: Long): ExtendedPrivateKey = ExtendedPrivateKey(bitcoin.DeterministicWallet.derivePrivateKey(parent.priv, index))

  /**
   *
   * @param parent extended public key
   * @param index  index of the child key
   * @return the derived public key at the specified index
   */
  def derivePublicKey(parent: ExtendedPublicKey, index: Long): ExtendedPublicKey = ExtendedPublicKey(bitcoin.DeterministicWallet.derivePublicKey(parent.pub, index))

  def derivePrivateKey(parent: ExtendedPrivateKey, chain: Seq[Long]): ExtendedPrivateKey = chain.foldLeft(parent)(derivePrivateKey)

  def derivePrivateKey(parent: ExtendedPrivateKey, keyPath: KeyPath): ExtendedPrivateKey = derivePrivateKey(parent, keyPath.path)

  def derivePublicKey(parent: ExtendedPublicKey, chain: Seq[Long]): ExtendedPublicKey = chain.foldLeft(parent)(derivePublicKey)

  def derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey = derivePublicKey(parent, keyPath.path)

  // p2pkh mainnet
  val xprv = 0x0488ade4
  val xpub = 0x0488b21e

  // p2sh-of-p2wpkh mainnet
  val yprv = 0x049d7878
  val ypub = 0x049d7cb2

  // p2wpkh mainnet
  val zprv = 0x04b2430c
  val zpub = 0x04b24746

  // p2pkh testnet
  val tprv = 0x04358394
  val tpub = 0x043587cf

  // p2sh-of-p2wpkh testnet
  val uprv = 0x044a4e28
  val upub = 0x044a5262

  // p2wpkh testnet
  val vprv = 0x045f18bc
  val vpub = 0x045f1cf6
}

