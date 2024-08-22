package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.scalacompat.KotlinUtils._
import scodec.bits.ByteVector

import java.io.OutputStream
import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
object DeterministicWallet {

  case class KeyPath(keyPath: bitcoin.KeyPath) {
    val path: Seq[Long] = keyPath.path.asScala.toList.map(_.longValue())

    def lastChildNumber: Long = keyPath.getLastChildNumber

    def derive(number: Long): KeyPath = KeyPath(keyPath.derive(number))

    override def toString: String = keyPath.toString
  }

  object KeyPath {
    val Root: KeyPath = KeyPath(new bitcoin.KeyPath(""))

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

    def extendedPublicKey: ExtendedPublicKey = ExtendedPublicKey(priv.getExtendedPublicKey)

    def derivePrivateKey(index: Long): ExtendedPrivateKey = ExtendedPrivateKey(priv.derivePrivateKey(index))

    def derivePrivateKey(path: Seq[Long]): ExtendedPrivateKey = ExtendedPrivateKey(priv.derivePrivateKey(path.map(x => Long.box(x)).toList.asJava))

    def derivePrivateKey(path: KeyPath): ExtendedPrivateKey = ExtendedPrivateKey(priv.derivePrivateKey(path))

    def derivePrivateKey(path: String): ExtendedPrivateKey = ExtendedPrivateKey(priv.derivePrivateKey(path))

    def encode(prefix: Int): String = priv.encode(prefix)

    def fingerprint: Long = priv.fingerprint()

    override def toString: String = priv.toString
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

  def encode(input: ExtendedPrivateKey, prefix: Int): String = input.encode(prefix)

  case class ExtendedPublicKey(pub: bitcoin.DeterministicWallet.ExtendedPublicKey) {
    val publickeybytes: ByteVector = pub.publickeybytes
    val chaincode: ByteVector32 = pub.chaincode
    val depth: Int = pub.depth
    val path: KeyPath = KeyPath(pub.path)
    val parent: Long = pub.parent

    def publicKey: PublicKey = pub.getPublicKey

    def derivePublicKey(index: Long): ExtendedPublicKey = ExtendedPublicKey(pub.derivePublicKey(index))

    def derivePublicKey(path: Seq[Long]): ExtendedPublicKey = ExtendedPublicKey(pub.derivePublicKey(path.map(x => Long.box(x)).toList.asJava))

    def derivePublicKey(path: KeyPath): ExtendedPublicKey = ExtendedPublicKey(pub.derivePublicKey(path))

    def derivePublicKey(path: String): ExtendedPublicKey = ExtendedPublicKey(pub.derivePublicKey(path))

    def encode(prefix: Int): String = pub.encode(prefix)

    def fingerprint: Long = pub.fingerprint()

    override def toString: String = pub.toString
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
  val xprv: Int = bitcoin.DeterministicWallet.xprv
  val xpub: Int = bitcoin.DeterministicWallet.xpub

  // p2sh-of-p2wpkh mainnet
  val yprv: Int = bitcoin.DeterministicWallet.yprv
  val ypub: Int = bitcoin.DeterministicWallet.ypub

  // p2wpkh mainnet
  val zprv: Int = bitcoin.DeterministicWallet.zprv
  val zpub: Int = bitcoin.DeterministicWallet.zpub

  // p2pkh testnet
  val tprv: Int = bitcoin.DeterministicWallet.tprv
  val tpub: Int = bitcoin.DeterministicWallet.tpub

  // p2sh-of-p2wpkh testnet
  val uprv: Int = bitcoin.DeterministicWallet.uprv
  val upub: Int = bitcoin.DeterministicWallet.upub

  // p2wpkh testnet
  val vprv: Int = bitcoin.DeterministicWallet.vprv
  val vpub: Int = bitcoin.DeterministicWallet.vpub
}

