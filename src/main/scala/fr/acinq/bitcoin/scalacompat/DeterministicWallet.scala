package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.scalacompat.KotlinUtils._
import fr.acinq.bitcoin.scalacompat.Protocol._
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

    def apply(path: Seq[Long]): KeyPath = KeyPath(new bitcoin.KeyPath(path.map(x => Long.box(x)).toList.asJava))

    /**
     *
     * @param path key path. A list of integers separated by a `/`. May start with "/" or "m/". A single quote appended
     *             at the end means use the hardened version of the ley index (example: m/44'/0'/0'/0)
     * @return a KeyPath instance
     */
    def apply(path: String): KeyPath = KeyPath(new bitcoin.KeyPath(path))
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

    def privateKey: PrivateKey = priv.getPrivateKey

    def publicKey: PublicKey = privateKey.publicKey

    override def toString = priv.toString
  }

  object ExtendedPrivateKey {
    def apply(secretkeybytes: ByteVector32, chaincode: ByteVector32, depth: Int, derivationPath: KeyPath, parent: Long): ExtendedPrivateKey = ExtendedPrivateKey(
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
    def apply(publicKey: ByteVector, chaincode: ByteVector32, depth: Int, derivationPath: KeyPath, parent: Long): ExtendedPublicKey = ExtendedPublicKey(
      new bitcoin.DeterministicWallet.ExtendedPublicKey(publicKey, chaincode, depth, derivationPath.keyPath, parent)
    )

    def decode(input: String, parentPath: KeyPath = KeyPath.Root): (Int, ExtendedPublicKey) = {
      val p = bitcoin.DeterministicWallet.ExtendedPublicKey.decode(input, parentPath.keyPath)
      (p.getFirst, ExtendedPublicKey(p.getSecond))
    }
  }

  def encode(input: ExtendedPublicKey, prefix: Int): String = bitcoin.DeterministicWallet.encode(input.pub, prefix)

  def write(input: ExtendedPublicKey, output: OutputStream): Unit = {
    fr.acinq.bitcoin.DeterministicWallet.write(input.pub, OutputStreamWrapper(output))
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

  def derivePrivateKey(parent: ExtendedPrivateKey, path: String): ExtendedPrivateKey = derivePrivateKey(parent, KeyPath(path))

  def derivePublicKey(parent: ExtendedPublicKey, chain: Seq[Long]): ExtendedPublicKey = chain.foldLeft(parent)(derivePublicKey)

  def derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey = derivePublicKey(parent, keyPath.path)

  def derivePublicKey(parent: ExtendedPublicKey, path: String): ExtendedPublicKey = derivePublicKey(parent, KeyPath(path))

  // p2pkh mainnet
  val xprv = bitcoin.DeterministicWallet.xprv
  val xpub = bitcoin.DeterministicWallet.xpub

  // p2sh-of-p2wpkh mainnet
  val yprv = bitcoin.DeterministicWallet.yprv
  val ypub = bitcoin.DeterministicWallet.ypub

  // p2wpkh mainnet
  val zprv = bitcoin.DeterministicWallet.zprv
  val zpub = bitcoin.DeterministicWallet.zpub

  // p2pkh testnet
  val tprv = bitcoin.DeterministicWallet.tprv
  val tpub = bitcoin.DeterministicWallet.tpub

  // p2sh-of-p2wpkh testnet
  val uprv = bitcoin.DeterministicWallet.uprv
  val upub = bitcoin.DeterministicWallet.upub

  // p2wpkh testnet
  val vprv = bitcoin.DeterministicWallet.vprv
  val vpub = bitcoin.DeterministicWallet.vpub
}

