package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger
import java.nio.ByteOrder

import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey, Scalar}
import fr.acinq.bitcoin.Protocol._

/**
  * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  */
object DeterministicWallet {

  case class KeyPath(path: Seq[Long]) {
    def lastChildNumber: Long = if (path.isEmpty) 0L else path.last

    def derive(number: Long) = KeyPath(path :+ number)

    def deriveHardened(number: Long) = KeyPath(path :+ hardened(number))

    override def toString = path.map(KeyPath.childNumberToString).foldLeft("m")(_ + "/" + _)
  }

  object KeyPath {
    val Root = KeyPath(Nil)
    def childNumberToString(childNumber: Long) = if (isHardened(childNumber)) ((childNumber - hardenedKeyIndex).toString + "'") else childNumber.toString
  }

  implicit def keypath2longseq(input: KeyPath): Seq[Long] = input.path

  implicit def longseq2keypath(input: Seq[Long]): KeyPath = KeyPath(input)

  val hardenedKeyIndex = 0x80000000L

  def hardened(index: Long): Long = hardenedKeyIndex + index

  def isHardened(index: Long): Boolean = index >= hardenedKeyIndex

  trait ExtendedKey {
    val chaincode: BinaryData
    val depth: Int
    val path: KeyPath
    val parent: Long
    def publicKey: PublicKey
    def extendedPublicKey: ExtendedPublicKey
  }

  case class ExtendedPrivateKey(secretkeybytes: BinaryData, chaincode: BinaryData, depth: Int, path: KeyPath, parent: Long) extends ExtendedKey {
    require(secretkeybytes.length == 32)
    require(chaincode.length == 32)

    def privateKey: PrivateKey = PrivateKey(Scalar(secretkeybytes), compressed = true)

    def publicKey: PublicKey = privateKey.publicKey

    def extendedPublicKey: ExtendedPublicKey = DeterministicWallet.publicKey(this)
  }

  case class ExtendedPublicKey(publickeybytes: BinaryData, chaincode: BinaryData, depth: Int, path: KeyPath, parent: Long) extends ExtendedKey {
    require(publickeybytes.length == 33)
    require(chaincode.length == 32)

    def publicKey: PublicKey = PublicKey(publickeybytes)

    def extendedPublicKey: ExtendedPublicKey = this
  }

  def encode(input: ExtendedPrivateKey, version: AddressVersion.Value): String = {
    val out = new ByteArrayOutputStream()
    writeUInt8(input.depth, out)
    writeUInt32(input.parent.toInt, out, ByteOrder.BIG_ENDIAN)
    writeUInt32(input.path.lastChildNumber.toInt, out, ByteOrder.BIG_ENDIAN)
    out.write(input.chaincode)
    out.write(0)
    out.write(input.secretkeybytes)
    val buffer = out.toByteArray
    Base58Check.encode(version.prv, buffer)
  }

  def encode(input: ExtendedPublicKey, version: AddressVersion.Value): String = {
    val out = new ByteArrayOutputStream()
    writeUInt8(input.depth, out)
    writeUInt32(input.parent.toInt, out, ByteOrder.BIG_ENDIAN)
    writeUInt32(input.path.lastChildNumber.toInt, out, ByteOrder.BIG_ENDIAN)
    out.write(input.chaincode)
    out.write(input.publickeybytes)
    val buffer = out.toByteArray
    Base58Check.encode(version.pub, buffer)
  }

  def decode(input: String, parentPath: KeyPath): (ExtendedKey, AddressVersion.Value) = {
    val (version, data) = Base58Check.decodeWithIntPrefix(input)
    val addressVersion = AddressVersion.values.find(v => v.prv == version || v.pub == version)
      .getOrElse(throw new IllegalArgumentException("requirement failed: invalid extended key version prefix"))
    val isPrivate = version == addressVersion.prv
    val in = new ByteArrayInputStream(data)
    val depth = uint8(in)
    val parentFingerprint = uint32(in, ByteOrder.BIG_ENDIAN)
    val childNumber = uint32(in, ByteOrder.BIG_ENDIAN)
    val chainCode = bytes(in, 32)
    val key = bytes(in, 33)
    if (isPrivate) {
      require(key.head == 0, "invalid private key")
      (ExtendedPrivateKey(key.tail, chainCode, depth, parentPath.derive(childNumber), parentFingerprint), addressVersion)
    } else {
      (ExtendedPublicKey(key, chainCode, depth, parentPath.derive(childNumber), parentFingerprint), addressVersion)
    }
  }

  /**
    *
    * @param seed random seed
    * @return a "master" private key
    */
  def generate(seed: Seq[Byte]): ExtendedPrivateKey = {
    val I = Crypto.hmac512("Bitcoin seed".getBytes("UTF-8"), seed)
    val IL = I.take(32)
    val IR = I.takeRight(32)
    ExtendedPrivateKey(IL, IR, depth = 0, path = List.empty[Long], parent = 0L)
  }

  /**
    *
    * @param input extended private key
    * @return the public key for this private key
    */
  def publicKey(input: ExtendedPrivateKey): ExtendedPublicKey = {
    ExtendedPublicKey(input.publicKey.toBin, input.chaincode, depth = input.depth, path = input.path, parent = input.parent)
  }

  /**
    *
    * @param input extended key
    * @return the fingerprint of the public key
    */
  def fingerprint(input: ExtendedKey): Long = uint32(new ByteArrayInputStream(Crypto.hash160(input.publicKey.toBin).take(4).reverse.toArray))

  /**
    *
    * @param parent extended private key
    * @param index  index of the child key
    * @return the derived private key at the specified index
    */
  def derivePrivateKey(parent: ExtendedPrivateKey, index: Long): ExtendedPrivateKey = {
    val I = if (isHardened(index)) {
      val buffer = 0.toByte +: parent.secretkeybytes.data
      Crypto.hmac512(parent.chaincode, buffer ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
    } else {
      val pub = publicKey(parent).publickeybytes
      Crypto.hmac512(parent.chaincode, pub.data ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
    }
    val IL = I.take(32)
    val IR = I.takeRight(32)
    val p = new BigInteger(1, IL.toArray)
    if (p.compareTo(Crypto.curve.getN) >= 0) {
      throw new RuntimeException("cannot generated child private key")
    }

    val key = Scalar(IL).add(parent.privateKey)
    if (key.isZero) {
      throw new RuntimeException("cannot generated child private key")
    }
    val buffer = key.toBin.take(32)
    ExtendedPrivateKey(buffer, chaincode = IR, depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
  }

  /**
    *
    * @param parent extended public key
    * @param index  index of the child key
    * @return the derived public key at the specified index
    */
  def derivePublicKey(parent: ExtendedKey, index: Long): ExtendedPublicKey = {
    require(!isHardened(index), "Cannot derive public keys from public hardened keys")

    val I = Crypto.hmac512(parent.chaincode, parent.publicKey.toBin.data ++ writeUInt32(index.toInt, ByteOrder.BIG_ENDIAN))
    val IL = I.take(32)
    val IR = I.takeRight(32)
    val p = new BigInteger(1, IL.toArray)
    if (p.compareTo(Crypto.curve.getN) >= 0) {
      throw new RuntimeException("cannot generated child public key")
    }
    val Ki = Scalar(p).toPoint.add(parent.publicKey)
    if (Ki.isInfinity) {
      throw new RuntimeException("cannot generated child public key")
    }
    val buffer = Ki.getEncoded(true)
    ExtendedPublicKey(buffer, chaincode = IR, depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
  }

  def derivePrivateKey(parent: ExtendedPrivateKey, chain: Seq[Long]): ExtendedPrivateKey = chain.foldLeft(parent)(derivePrivateKey)

  def derivePublicKey(parent: ExtendedKey, chain: Seq[Long]): ExtendedPublicKey = chain.foldLeft(parent.extendedPublicKey)(derivePublicKey)

}


object AddressVersion extends Enumeration {
  protected case class Val(prv: Int, pub: Int, testnet: Boolean) extends super.Val
  implicit def valueToVal(x: Value): Val = x.asInstanceOf[Val]

  // mainnet
  protected val xprv = 0x0488ade4
  protected val xpub = 0x0488b21e

  // testnet
  protected val tprv = 0x04358394
  protected val tpub = 0x043587cf

  // segwit mainnet (P2WPKH in P2SH)
  protected val yprv = 0x049d7878
  protected val ypub = 0x049d7cb2

  // segwit testnet (P2WPKH in P2SH)
  protected val uprv = 0x044a4e28
  protected val upub = 0x044a5262

  val MainNetP2PKH        = Val(xprv, xpub, false)
  val MainNetP2WPKHinP2SH = Val(yprv, ypub, false)
  val TestNetP2PKH        = Val(tprv, tpub, true)
  val TestNetP2WPKHinP2SH = Val(uprv, upub, true)
}