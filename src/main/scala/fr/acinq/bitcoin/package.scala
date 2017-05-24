package fr.acinq

import java.io._
import java.math.BigInteger

import org.spongycastle.util.encoders.Hex

/**
  * see https://en.bitcoin.it/wiki/Protocol_specification
  */
package object bitcoin {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney = 21000000 * Coin
  val MaxScriptElementSize = 520
  val MaxBlockSize = 1000000
  val LockTimeThreshold = 500000000L

  /**
    * signature hash flags
    */
  val SIGHASH_ALL = 1
  val SIGHASH_NONE = 2
  val SIGHASH_SINGLE = 3
  val SIGHASH_ANYONECANPAY = 0x80

  object Hash {
    val Zeroes: BinaryData = "0000000000000000000000000000000000000000000000000000000000000000"
    val One: BinaryData = "0100000000000000000000000000000000000000000000000000000000000000"
  }

  object SigVersion {
    val SIGVERSION_BASE = 0
    val SIGVERSION_WITNESS_V0 = 1
  }

  implicit object NumericSatoshi extends Numeric[Satoshi] {
    // @formatter:off
    override def plus(x: Satoshi, y: Satoshi): Satoshi = x + y
    override def toDouble(x: Satoshi): Double = x.toLong
    override def toFloat(x: Satoshi): Float = x.toLong
    override def toInt(x: Satoshi): Int = x.toLong.toInt
    override def negate(x: Satoshi): Satoshi = Satoshi(-x.amount)
    override def fromInt(x: Int): Satoshi = Satoshi(x)
    override def toLong(x: Satoshi): Long = x.toLong
    override def times(x: Satoshi, y: Satoshi): Satoshi = ???
    override def minus(x: Satoshi, y: Satoshi): Satoshi = ???
    override def compare(x: Satoshi, y: Satoshi): Int = x.compare(y)
    // @formatter:on
  }

  implicit final class SatoshiLong(private val n: Long) extends AnyVal {
    def satoshi = Satoshi(n)
  }

  implicit final class MilliSatoshiLong(private val n: Long) extends AnyVal {
    def millisatoshi = MilliSatoshi(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc = Btc(n)
  }

  implicit final class MilliBtcDouble(private val n: Double) extends AnyVal {
    def millibtc = MilliBtc(n)
  }

  implicit def satoshi2btc(input: Satoshi): Btc = Btc(BigDecimal(input.amount) / Coin)

  implicit def btc2satoshi(input: Btc): Satoshi = Satoshi((input.amount * Coin).toLong)

  implicit def satoshi2millibtc(input: Satoshi): MilliBtc = btc2millibtc(satoshi2btc(input))

  implicit def millibtc2satoshi(input: MilliBtc): Satoshi = btc2satoshi(millibtc2btc(input))

  implicit def btc2millibtc(input: Btc): MilliBtc = MilliBtc(input.amount * 1000L)

  implicit def millibtc2btc(input: MilliBtc): Btc = Btc(input.amount / 1000L)

  implicit def satoshi2millisatoshi(input: Satoshi): MilliSatoshi = MilliSatoshi(input.amount * 1000L)

  implicit def millisatoshi2satoshi(input: MilliSatoshi): Satoshi = Satoshi(input.amount / 1000L)

  implicit def btc2millisatoshi(input: Btc): MilliSatoshi = satoshi2millisatoshi(btc2satoshi(input))

  implicit def millisatoshi2btc(input: MilliSatoshi): Btc = satoshi2btc(millisatoshi2satoshi(input))

  implicit def millibtc2millisatoshi(input: MilliBtc): MilliSatoshi = satoshi2millisatoshi(millibtc2satoshi(input))

  implicit def millisatoshi2millibtc(input: MilliSatoshi): MilliBtc = satoshi2millibtc(millisatoshi2satoshi(input))

  def toHexString(blob: BinaryData) = Hex.toHexString(blob)

  def fromHexString(hex: String): BinaryData = Hex.decode(hex.stripPrefix("0x"))

  implicit def string2binaryData(input: String): BinaryData = BinaryData(fromHexString(input))

  implicit def seq2binaryData(input: Seq[Byte]): BinaryData = BinaryData(input)

  implicit def array2binaryData(input: Array[Byte]): BinaryData = BinaryData(input)

  implicit def binaryData2array(input: BinaryData): Array[Byte] = input.data.toArray

  implicit def binaryData2Seq(input: BinaryData): Seq[Byte] = input.data

  /**
    *
    * @param input compact size encoded integer as used to encode proof-of-work difficulty target
    * @return a (result, isNegative, overflow) tuple were result is the decoded integer
    */
  def decodeCompact(input: Long): (BigInteger, Boolean, Boolean) = {
    val nSize = (input >> 24).toInt
    val (nWord, result) = if (nSize <= 3) {
      val nWord1 = (input & 0x007fffffL) >> 8 * (3 - nSize)
      (nWord1, BigInteger.valueOf(nWord1))
    } else {
      val nWord1 = (input & 0x007fffffL)
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE
}
