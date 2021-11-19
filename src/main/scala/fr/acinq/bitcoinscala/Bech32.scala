package fr.acinq.bitcoinscala

import fr.acinq.bitcoin
import scodec.bits.ByteVector

/**
 * Bech32 and Bech32m address formats.
 * See https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki and https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki.
 */
object Bech32 {
  val alphabet = bitcoin.Bech32.alphabet

  // @formatter:off
  sealed trait Encoding
  case object Bech32Encoding extends Encoding
  case object Bech32mEncoding extends Encoding
  // @formatter:on

  implicit def scala2kmp(encoding: Encoding): bitcoin.Bech32.Encoding = encoding match {
    case Bech32Encoding => bitcoin.Bech32.Encoding.Bech32
    case Bech32mEncoding => bitcoin.Bech32.Encoding.Bech32m
  }

  implicit def kmp2scala(encoding: bitcoin.Bech32.Encoding) = encoding match {
    case bitcoin.Bech32.Encoding.Bech32 => Bech32Encoding
    case bitcoin.Bech32.Encoding.Bech32m => Bech32mEncoding
  }

  // 5 bits integer
  // Bech32 works with 5 bits values, we use this type to make it explicit: whenever you see Int5 it means 5 bits values,
  // and whenever you see Byte it means 8 bits values
  type Int5 = Byte


  /**
   * @param hrp   human readable prefix
   * @param int5s 5-bit data
   * @return hrp + data encoded as a Bech32 string
   */
  def encode(hrp: String, int5s: Array[Int5], encoding: Encoding): String = bitcoin.Bech32.encode(hrp, int5s, encoding)

  /**
   * decodes a bech32 or bech32m string
   *
   * @param bech32 bech32 or bech32m string
   * @return a (encoding, hrp, data) tuple
   */
  def decode(bech32: String): (String, Array[Int5], Encoding) = {
    val decoded = bitcoin.Bech32.decode(bech32)
    (decoded.getFirst, decoded.getSecond.map(_.byteValue()), decoded.getThird)
  }


  /**
   * @param input a sequence of 8 bits integers
   * @return a sequence of 5 bits integers
   */
  def eight2five(input: Array[Byte]): Array[Int5] = bitcoin.Bech32.eight2five(input).map(_.byteValue())

  /**
   * @param input a sequence of 5 bits integers
   * @return a sequence of 8 bits integers
   */
  def five2eight(input: Array[Int5]): Array[Byte] = bitcoin.Bech32.five2eight(input.map(_.byteValue()), 0)

    /**
   * encode a bitcoin witness address
   *
   * @param hrp            should be "bc" or "tb"
   * @param witnessVersion witness version (0 to 16)
   * @param data           witness program: if version is 0, either 20 bytes (P2WPKH) or 32 bytes (P2WSH)
   * @return a bech32 encoded witness address
   */
  def encodeWitnessAddress(hrp: String, witnessVersion: Byte, data: ByteVector): String = bitcoin.Bech32.encodeWitnessAddress(hrp, witnessVersion, data.toArray)

  /**
   * decode a bitcoin witness address
   *
   * @param address witness address
   * @return a (prefix, version, program) tuple where prefix is the human-readable prefix, version
   *         is the witness version and program the decoded witness program.
   *         If version is 0, it will be either 20 bytes (P2WPKH) or 32 bytes (P2WSH).
   */
  def decodeWitnessAddress(address: String): (String, Byte, ByteVector) = {
    val decoded = bitcoin.Bech32.decodeWitnessAddress(address)
    (decoded.getFirst, decoded.getSecond, ByteVector.view(decoded.getThird))
  }
}
