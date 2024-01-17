package fr.acinq.bitcoin

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.bitcoin.scalacompat.KotlinUtils._
import scodec.bits.ByteVector

import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */
package object scalacompat {

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
    def sat: Satoshi = Satoshi(n)
  }

  implicit final class MilliBtcDouble(private val n: Double) extends AnyVal {
    def millibtc: MilliBtc = MilliBtc(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc: Btc = Btc(n)
  }

  // @formatter:off
  implicit def satoshi2btc(input: Satoshi): Btc = input.toBtc
  implicit def btc2satoshi(input: Btc): Satoshi = input.toSatoshi
  implicit def satoshi2millibtc(input: Satoshi): MilliBtc = input.toMilliBtc
  implicit def millibtc2satoshi(input: MilliBtc): Satoshi = input.toSatoshi
  implicit def btc2millibtc(input: Btc): MilliBtc = input.toMilliBtc
  implicit def millibtc2btc(input: MilliBtc): Btc = input.toBtc
  // @formatter:on

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SigHash.SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == bitcoin.SigHash.SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == bitcoin.SigHash.SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: BlockHash): String = bitcoin.Bitcoin.computeP2PkhAddress(pub, chainHash)

  def computeBIP44Address(pub: PublicKey, chainHash: BlockHash): String = computeP2PkhAddress(pub, chainHash)

  /**
   * @param pub       public key
   * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
   * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most bitcoin wallets
   */
  def computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: BlockHash): String = bitcoin.Bitcoin.computeP2ShOfP2WpkhAddress(pub, chainHash)

  def computeBIP49Address(pub: PublicKey, chainHash: BlockHash): String = computeP2ShOfP2WpkhAddress(pub, chainHash)

  /**
   * @param pub       public key
   * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
   * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
   *         understood only by native sewgit wallets
   */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: BlockHash): String = bitcoin.Bitcoin.computeP2WpkhAddress(pub, chainHash)

  def computeBIP84Address(pub: PublicKey, chainHash: BlockHash): String = computeP2WpkhAddress(pub, chainHash)

  /**
   * @param chainHash hash of the chain (i.e. hash of the genesis block of the chain we're on)
   * @param script    public key script
   * @return the address of this public key script on this chain
   */
  def computeScriptAddress(chainHash: BlockHash, script: Seq[ScriptElt]): Either[fr.acinq.bitcoin.BitcoinError, String] = addressFromPublicKeyScript(chainHash, script)

  /**
   * @param chainHash hash of the chain (i.e. hash of the genesis block of the chain we're on)
   * @param script    public key script
   * @return the address of this public key script on this chain
   */
  def computeScriptAddress(chainHash: BlockHash, script: ByteVector): Either[fr.acinq.bitcoin.BitcoinError, String] = computeScriptAddress(chainHash, Script.parse(script))

  def addressToPublicKeyScript(chainHash: BlockHash, address: String): Either[fr.acinq.bitcoin.BitcoinError, Seq[ScriptElt]] = fr.acinq.bitcoin.Bitcoin.addressToPublicKeyScript(chainHash, address).map(_.asScala.map(kmp2scala).toList)

  def addressFromPublicKeyScript(chainHash: BlockHash, script: Seq[ScriptElt]): Either[fr.acinq.bitcoin.BitcoinError, String] = fr.acinq.bitcoin.Bitcoin.addressFromPublicKeyScript(chainHash, script.map(scala2kmp).asJava)
}
