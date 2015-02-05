package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.math.BigInteger

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.ECPoint

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
object DeterministicWallet {

  case class ExtendedPrivateKey(secretkey: BinaryData, chaincode: BinaryData, depth: Int, index: Long, parent: Long)

  case class ExtendedPublicKey(publickey: BinaryData, chaincode: BinaryData, depth: Int, index: Long, parent: Long)

  def encode(input: ExtendedPrivateKey, testnet: Boolean): String = {
    val out = new ByteArrayOutputStream()
    writeUInt32BigEndian(if (testnet) tprv else xprv, out)
    writeUInt8(input.depth, out)
    writeUInt32BigEndian(input.parent, out)
    writeUInt32BigEndian(input.index, out)
    out.write(input.chaincode)
    out.write(0)
    out.write(input.secretkey)
    val buffer = out.toByteArray
    val checksum = Crypto.hash256(buffer).take(4)
    Base58.encode(buffer ++ checksum)
  }

  def encode(input: ExtendedPublicKey, testnet: Boolean): String = {
    val out = new ByteArrayOutputStream()
    writeUInt32BigEndian(if (testnet) tpub else xpub, out)
    writeUInt8(input.depth, out)
    writeUInt32BigEndian(input.parent, out)
    writeUInt32BigEndian(input.index, out)
    out.write(input.chaincode)
    out.write(input.publickey)
    val buffer = out.toByteArray
    val checksum = Crypto.hash256(buffer).take(4)
    Base58.encode(buffer ++ checksum)
  }

  /**
   *
   * @param seed random seed
   * @return a "master" private key
   */
  def generate(seed: Array[Byte]): ExtendedPrivateKey = {
    val I = hmac512("Bitcoin seed".getBytes("UTF-8"), seed)
    val IL = I.take(32)
    val IR = I.takeRight(32)
    ExtendedPrivateKey(IL, IR, depth = 0, index = 0L, parent = 0L)
  }

  /**
   *
   * @param input extended private key
   * @return the public key for this private key
   */
  def publicKey(input: ExtendedPrivateKey) : ExtendedPublicKey = {
    // add an extra 1 to make sure the returned public key will be encoded
    // in compressed format as per specs.
    val pub = Crypto.publicKeyFromPrivateKey(input.secretkey.data :+ 1.toByte)
    ExtendedPublicKey(pub, input.chaincode, depth = input.depth, index = input.index, parent = input.parent)
  }

  /**
   *
   * @param input extended public key
   * @return the fingerprint for this public key
   */
  def fingerprint(input: ExtendedPublicKey): Long = uint32(Crypto.hash160(input.publickey).take(4).reverse)

  /**
   *
   * @param input extended private key
   * @return the fingerprint for this private key (which is based on the corresponding public key)
   */
  def fingerprint(input: ExtendedPrivateKey): Long = fingerprint(publicKey(input))

  /**
   *
   * @param parent extended private key
   * @param index index of the child key
   * @return the derived private key at the specified index
   */
  def derivePrivateKey(parent: ExtendedPrivateKey, index: Long) = {
    val I = if (index >= 0x80000000L) {
      val buffer = 0.toByte +: parent.secretkey.data
      hmac512(parent.chaincode, buffer ++ writeUInt32BigEndian(index))
    } else {
      val pub = publicKey(parent).publickey
      hmac512(parent.chaincode, pub.data ++ writeUInt32BigEndian(index))
    }
    val IL = I.take(32)
    val IR = I.takeRight(32)
    val key = new BigInteger(1, IL).add(new BigInteger(1, parent.secretkey)).mod(Crypto.curve.getN) // Crypto.curve should not be used like this...
    val buffer = key.toByteArray.dropWhile(_ == 0) // BigInteger.toByteArray may add a leading 0x00
    ExtendedPrivateKey(buffer, chaincode = IR, depth = parent.depth + 1, index = index, parent = fingerprint(parent))
  }

  /**
   *
   * @param parent extended public key
   * @param index index of the child key
   * @return the derived public key at the specified index
   */
  def derivePublicKey(parent: ExtendedPublicKey, index: Long) : ExtendedPublicKey = {
    require(index < 0x80000000L, "Cannot derive public keys from public hardened keys")

    val I = hmac512(parent.chaincode, parent.publickey.data ++ writeUInt32BigEndian(index))
    val IL = I.take(32)
    val IR = I.takeRight(32)
    val p = new BigInteger(1, IL)
    if (p.compareTo(Crypto.curve.getN) == 1) {
      throw new RuntimeException("cannot generated child public key")
    }
    val Ki = point(p).add(Crypto.curve.getCurve.decodePoint(parent.publickey))
    if (Ki.isInfinity) {
      throw new RuntimeException("cannot generated child public key")
    }
    val buffer = Ki.getEncoded(true)
    ExtendedPublicKey(buffer, chaincode = IR, depth = parent.depth + 1, index = index, parent = fingerprint(parent))
  }

  def derivePrivateKey(parent: ExtendedPrivateKey, chain: List[Long]): ExtendedPrivateKey = chain.foldLeft(parent)(derivePrivateKey)

  def derivePublicKey(parent: ExtendedPublicKey, chain: List[Long]): ExtendedPublicKey = chain.foldLeft(parent)(derivePublicKey)

  def hmac512(key: Array[Byte], data: Array[Byte]) : Array[Byte] = {
    val mac = new HMac(new SHA512Digest())
    mac.init(new KeyParameter(key))
    mac.update(data, 0, data.length)
    val out = new Array[Byte](64)
    mac.doFinal(out, 0)
    out
  }

  private def point(p: BigInteger): ECPoint = Crypto.curve.getG.multiply(p)

  private def serp(p: ECPoint): Array[Byte] = p.getEncoded(true)

  val xprv = 0x0488ade4
  val tprv = 0x04358394
  val xpub = 0x0488b21e
  val tpub = 0x043587cf
}

