package fr.acinq.bitcoinscala

import fr.acinq.bitcoin
import scodec.bits.ByteVector

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
    val PubkeyAddress = bitcoin.Base58.Prefix.PubkeyAddress
    val ScriptAddress = bitcoin.Base58.Prefix.ScriptAddress
    val SecretKey = bitcoin.Base58.Prefix.SecretKey
    val PubkeyAddressTestnet = bitcoin.Base58.Prefix.PubkeyAddressTestnet
    val ScriptAddressTestnet = bitcoin.Base58.Prefix.ScriptAddressTestnet
    val SecretKeyTestnet = bitcoin.Base58.Prefix.SecretKeyTestnet
    val PubkeyAddressSegnet = bitcoin.Base58.Prefix.PubkeyAddressSegnet
    val ScriptAddressSegnet = bitcoin.Base58.Prefix.ScriptAddressSegnet
    val SecretKeySegnet = bitcoin.Base58.Prefix.SecretKeySegnet
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
  /**
    * Encode data in Base58Check format.
    * For example, to create an address from a public key you could use:
    *
    * @param prefix version prefix (one byte)
    * @param data   date to be encoded
    * @return a Base58 string
    */
  def encode(prefix: Byte, data: ByteVector): String = encode(ByteVector(prefix), data)

  /**
    *
    * @param prefix version prefix (integer, as used with BIP32 ExtendedKeys for example)
    * @param data   data to be encoded
    * @return a Base58 String
    */
  def encode(prefix: Int, data: ByteVector): String = bitcoin.Base58Check.encode(prefix, data.toArray)
  /**
    *
    * @param prefix version prefix (several bytes, as used with BIP32 ExtendedKeys for example)
    * @param data   data to be encoded
    * @return a Base58 String
    */
  def encode(prefix: ByteVector, data: ByteVector): String = bitcoin.Base58Check.encode(prefix.toArray, data.toArray)
  /**
    * Decodes Base58 data that has been encoded with a single byte prefix
    *
    * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
    *
    * @param encoded encoded data
    * @return a (prefix, data) tuple
    */
  def decode(encoded: String): (Byte, ByteVector) = {
    val decoded = bitcoin.Base58Check.decodeWithPrefixLen(encoded, 1)
    (decoded.getFirst.head, ByteVector.view(decoded.getSecond))
  }

  /**
    * Decodes Base58 data that has been encoded with an integer prefix
    *
    * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
    *
    * @param encoded encoded data
    * @return a (prefix, data) tuple
    */
  def decodeWithIntPrefix(encoded: String): (Int, ByteVector) = {
    val decoded = bitcoin.Base58Check.decodeWithIntPrefix(encoded)
    (decoded.getFirst, ByteVector.view(decoded.getSecond))
  }

  /**
    * Decodes Base58 data that has been encoded with several bytes prefix
    *
    * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
    *
    * @param encoded encoded data
    * @return a (prefix, data) tuple
    */
  def decodeWithPrefixLen(encoded: String, prefixLen: Int): (ByteVector, ByteVector) = {
    val decoded = bitcoin.Base58Check.decodeWithPrefixLen(encoded, prefixLen)
    (ByteVector.view(decoded.getFirst), ByteVector.view(decoded.getSecond))
  }
}