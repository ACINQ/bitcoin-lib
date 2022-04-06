package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import scodec.bits.ByteVector

import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */
object MnemonicCode {
  /**
   * BIP39 entropy encoding using default word list.
   *
   * @param entropy input entropy
   * @return a list of mnemonic words that encodes the input entropy
   */
  def toMnemonics(entropy: ByteVector): List[String] = bitcoin.MnemonicCode.toMnemonics(entropy.toArray).asScala.toList

  /**
   * BIP39 entropy encoding.
   *
   * @param entropy  input entropy
   * @param wordlist word list (must be 2048 words long)
   * @return a list of mnemonic words that encodes the input entropy
   */
  def toMnemonics(entropy: ByteVector, wordlist: Seq[String]): List[String] = bitcoin.MnemonicCode.toMnemonics(entropy.toArray, wordlist.asJava).asScala.toList

  /**
   * Verify that a mnemonic seed is valid using default BIP39 word list.
   */
  def validate(mnemonics: String): Unit = bitcoin.MnemonicCode.validate(mnemonics)

  /**
   * Verify that a mnemonic seed is valid using default BIP39 word list.
   */
  def validate(mnemonics: Seq[String]): Unit = bitcoin.MnemonicCode.validate(mnemonics.mkString(" "))

  /**
   * Verify that a mnemonic seed is valid.
   *
   * @param mnemonics list of mnemonic words.
   * @param wordlist  word list (must be 2048 words long)
   */
  def validate(mnemonics: Seq[String], wordlist: Seq[String]): Unit = bitcoin.MnemonicCode.validate(mnemonics.asJava, wordlist.asJava)

  /**
   * BIP39 seed derivation.
   *
   * @param mnemonics  mnemonic words
   * @param passphrase passphrase
   * @return a seed derived from the mnemonic words and passphrase
   */
  def toSeed(mnemonics: Seq[String], passphrase: String): ByteVector = ByteVector.view(bitcoin.MnemonicCode.toSeed(mnemonics.asJava, passphrase))

  /**
   * BIP39 seed derivation.
   *
   * @param mnemonics  mnemonic words
   * @param passphrase passphrase
   * @return a seed derived from the mnemonic words and passphrase
   */
  def toSeed(mnemonics: String, passphrase: String): ByteVector = ByteVector.view(bitcoin.MnemonicCode.toSeed(mnemonics, passphrase))
}
