package fr.acinq.bitcoin

import java.math.BigInteger

import scala.annotation.tailrec

/*
 * see https://en.bitcoin.it/wiki/Base58Check_encoding
 *
 * Why base-58 instead of standard base-64 encoding?
 * <ul>
 * <li>Don't want 0OIl characters that look the same in some fonts and could be used to create visually identical
 * looking account numbers.</li>
 * <li>A string with non-alphanumeric characters is not as easily accepted as an account number.</li>
 * <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>Doubleclicking selects the whole number as one word if it's all alphanumeric.</li>
 */
object Base58 {

  object Prefix {
    val PubkeyAddress = 0.toByte
    val ScriptAddress = 5.toByte
    val SecretKey = 128.toByte
    val PubkeyAddressTestnet = 111.toByte
    val ScriptAddressTestnet = 196.toByte
    val SecretKeyTestnet = 239.toByte
    val PubkeyAddressSegnet = 30.toByte
    val ScriptAddressSegnet = 50.toByte
    val SecretKeySegnet = 158.toByte
  }

  val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  // char -> value
  val map = alphabet.zipWithIndex.toMap

  /**
    *
    * @param input binary data
    * @return the base-58 representation of input
    */
  def encode(input: Seq[Byte]): String = {
    if (input.isEmpty) ""
    else {
      val big = new BigInteger(1, input.toArray)
      val builder = new StringBuilder

      @tailrec
      def encode1(current: BigInteger): Unit = current match {
        case BigInteger.ZERO => ()
        case _ =>
          val Array(x, remainder) = current.divideAndRemainder(BigInteger.valueOf(58L))
          builder.append(alphabet.charAt(remainder.intValue))
          encode1(x)
      }

      encode1(big)
      input.takeWhile(_ == 0).map(_ => builder.append(alphabet.charAt(0)))
      builder.toString().reverse
    }
  }

  /**
    *
    * @param input base-58 encoded data
    * @return the decoded data
    */
  def decode(input: String): BinaryData = {
    val zeroes = input.takeWhile(_ == '1').map(_ => 0: Byte).toArray
    val trim = input.dropWhile(_ == '1').toList
    val decoded = trim.foldLeft(BigInteger.ZERO)((a, b) => a.multiply(BigInteger.valueOf(58L)).add(BigInteger.valueOf(map(b))))
    if (trim.isEmpty) zeroes else zeroes ++ decoded.toByteArray.dropWhile(_ == 0) // BigInteger.toByteArray may add a leading 0x00
  }
}

/**
  * https://en.bitcoin.it/wiki/Base58Check_encoding
  * Base58Check is a format based on Base58 and used a lot in bitcoin, for encoding addresses and private keys for
  * example. It includes a prefix (usually a single byte) and a checksum so you know what has been encoded, and that it has
  * been transmitted correctly.
  * For example, to create an address for a public key you could write:
  * {{{
  *   val pub: BinaryData = "0202a406624211f2abbdc68da3df929f938c3399dd79fac1b51b0e4ad1d26a47aa"
  *   val address = Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(pub))
  * }}}
  * And to decode a private key you could write:
  * {{{
  *   // check that is it a mainnet private key
  *   val (Base58.Prefix.SecretKey, priv) = Base58Check.decode("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn")
  * }}}
  *
  */
object Base58Check {
  def checksum(data: Seq[Byte]) = Crypto.hash256(data).take(4)

  /**
    * Encode data in Base58Check format.
    * For example, to create an address from a public key you could use:
    *
    * @param prefix version prefix (one byte)
    * @param data   date to be encoded
    * @return a Base58 string
    */
  def encode(prefix: Byte, data: Seq[Byte]): String = {
    val prefixAndData = prefix +: data
    Base58.encode(prefixAndData ++ checksum(prefixAndData))
  }

  /**
    *
    * @param prefix version prefix (several bytes, as used with BIP32 ExtendedKeys for example)
    * @param data   data to be encoded
    * @return a Base58 String
    */
  def encode(prefix: Seq[Byte], data: Seq[Byte]): String = {
    val prefixAndData = prefix ++ data
    Base58.encode(prefixAndData ++ checksum(prefixAndData))
  }

  /**
    * Decodes Base58 data that has been encoded with a single byte prefix
    *
    * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
    *
    * @param encoded encoded data
    * @return a (prefix, data) tuple
    */
  def decode(encoded: String): (Byte, BinaryData) = {
    val raw = Base58.decode(encoded)
    val versionAndHash = raw.dropRight(4)
    val checksum = raw.takeRight(4)
    require(checksum == Base58Check.checksum(versionAndHash), s"invalid Base58Check data $encoded")
    (versionAndHash(0), versionAndHash.tail)
  }
}