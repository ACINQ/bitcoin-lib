package fr.acinq

import fr.acinq.bitcoinscala.Crypto.PublicKey
import fr.acinq.bitcoinscala.KotlinUtils._
import scodec.bits.ByteVector

import java.math.BigInteger
import scala.jdk.CollectionConverters.SeqHasAsJava

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */
package object bitcoinscala {

  implicit object NumericSatoshi extends Numeric[Satoshi] {
    // @formatter:off
    override def compare(x: Satoshi, y: Satoshi): Int = x.compare(y)
    override def minus(x: Satoshi, y: Satoshi): Satoshi = x - y
    override def negate(x: Satoshi): Satoshi = -x
    override def plus(x: Satoshi, y: Satoshi): Satoshi = x + y
    override def times(x: Satoshi, y: Satoshi): Satoshi = x * y.toLong
    override def toDouble(x: Satoshi): Double = x.toLong.toDouble
    override def toFloat(x: Satoshi): Float = x.toLong.toFloat
    override def toInt(x: Satoshi): Int = x.toLong.toInt
    override def toLong(x: Satoshi): Long = x.toLong
    override def fromInt(x: Int): Satoshi = Satoshi(x)
    override def parseString(str: String): Option[Satoshi] = None
    // @formatter:on
  }

  implicit final class SatoshiLong(private val n: Long) extends AnyVal {
    def sat = Satoshi(n)
  }

  implicit final class MilliBtcDouble(private val n: Double) extends AnyVal {
    def millibtc = MilliBtc(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc = Btc(n)
  }

  // @formatter:off
  implicit def satoshi2btc(input: Satoshi): Btc = input.toBtc
  implicit def btc2satoshi(input: Btc): Satoshi = input.toSatoshi
  implicit def satoshi2millibtc(input: Satoshi): MilliBtc = input.toMilliBtc
  implicit def millibtc2satoshi(input: MilliBtc): Satoshi = input.toSatoshi
  implicit def btc2millibtc(input: Btc): MilliBtc = input.toMilliBtc
  implicit def millibtc2btc(input: MilliBtc): Btc = input.toBtc
  // @formatter:on

  /**
   * @param input compact size encoded integer as used to encode proof-of-work difficulty target
   * @return a (result, isNegative, overflow) tuple were result is the decoded integer
   */
  def decodeCompact(input: Long): (BigInteger, Boolean, Boolean) = {
    val nSize = (input >> 24).toInt
    val (nWord, result) = if (nSize <= 3) {
      val nWord1 = (input & 0x007fffffL) >> 8 * (3 - nSize)
      (nWord1, BigInteger.valueOf(nWord1))
    } else {
      val nWord1 = input & 0x007fffffL
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  /**
   * @param value input value
   * @return the compact encoding of the input value. this is used to encode proof-of-work target into the `bits`
   *         block header field
   */
  def encodeCompact(value: BigInteger): Long = {
    var size = value.toByteArray.length
    var compact = if (size <= 3) value.longValue << 8 * (3 - size) else value.shiftRight(8 * (size - 3)).longValue
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if ((compact & 0x00800000L) != 0) {
      compact >>= 8
      size += 1
    }
    compact |= size << 24
    compact |= (if (value.signum() == -1) 0x00800000 else 0)
    compact
  }

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & bitcoin.SigHash.SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == bitcoin.SigHash.SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == bitcoin.SigHash.SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = bitcoin.Bitcoin.computeP2PkhAddress(pub, chainHash)

  def computeBIP44Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2PkhAddress(pub, chainHash)

  /**
   * @param pub       public key
   * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
   * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most bitcoin wallets
   */
  def computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = bitcoin.Bitcoin.computeP2ShOfP2WpkhAddress(pub, chainHash)

  def computeBIP49Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2ShOfP2WpkhAddress(pub, chainHash)

  /**
   * @param pub       public key
   * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
   * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
   *         understood only by native sewgit wallets
   */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = bitcoin.Bitcoin.computeP2WpkhAddress(pub, chainHash)

  def computeBIP84Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2WpkhAddress(pub, chainHash)

  /**
   * @param chainHash hash of the chain (i.e. hash of the genesis block of the chain we're on)
   * @param script    public key script
   * @return the address of this public key script on this chain
   */
  def computeScriptAddress(chainHash: ByteVector32, script: Seq[ScriptElt]): String = {
    // TODO: addressFromPublicKeyScript behaves differently and can return null, this should be changed
    val address = bitcoin.Bitcoin.addressFromPublicKeyScript(chainHash, script.map(scala2kmp).asJava)
    require(address != null, "invalid chain hash or script")
    address
  }

  /**
   * @param chainHash hash of the chain (i.e. hash of the genesis block of the chain we're on)
   * @param script    public key script
   * @return the address of this public key script on this chain
   */
  def computeScriptAddress(chainHash: ByteVector32, script: ByteVector): String = computeScriptAddress(chainHash, Script.parse(script))

}
