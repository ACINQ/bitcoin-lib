package fr.acinq

import java.math.BigInteger

import fr.acinq.bitcoin.Crypto.PublicKey

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

  /**
    *
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

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
    }
  }

  def computeBIP44Address(pub: PublicKey, chainHash: ByteVector32) = computeP2PkhAddress(pub, chainHash)

  /**
    *
    * @param pub       public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most bitcoin wallets
    */
  def computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val script = Script.pay2wpkh(pub)
    val hash = Crypto.hash160(Script.write(script))
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddress, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP49Address(pub: PublicKey, chainHash: ByteVector32) = computeP2ShOfP2WpkhAddress(pub, chainHash)

  /**
    *
    * @param pub       public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
    *         understood only by native sewgit wallets
    */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "bc"
      case Block.TestnetGenesisBlock.hash => "tb"
      case Block.RegtestGenesisBlock.hash => "bcrt"
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
    Bech32.encodeWitnessAddress(hrp, 0, hash)
  }

  def computeBIP84Address(pub: PublicKey, chainHash: ByteVector32) = computeP2WpkhAddress(pub, chainHash)
}
