package fr.acinq.bitcoinscala

import scodec.bits.ByteVector

import scala.io.Source
import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */
object MnemonicCode {
  lazy val englishWordlist = {
    val stream = MnemonicCode.getClass.getResourceAsStream("/bip39_english_wordlist.txt")
    Source.fromInputStream(stream, "UTF-8").getLines().toSeq
  }

  /**
   * BIP39 entropy encoding
   *
   * @param entropy  input entropy
   * @param wordlist word list (must be 2048 words long)
   * @return a list of mnemonic words that encodes the input entropy
   */
  def toMnemonics(entropy: ByteVector, wordlist: Seq[String] = englishWordlist): List[String] = fr.acinq.bitcoin.MnemonicCode.toMnemonics(entropy.toArray, wordlist.asJava).asScala.toList

  /**
   * validate that a mnemonic seed is valid
   *
   * @param mnemonics list of mnemomic words
   *
   */
  def validate(mnemonics: Seq[String], wordlist: Seq[String] = englishWordlist): Unit = fr.acinq.bitcoin.MnemonicCode.validate(mnemonics.asJava, wordlist.asJava)

  def validate(mnemonics: String): Unit = validate(mnemonics.split(" ").toSeq)

  /**
   * BIP39 seed derivation
   *
   * @param mnemonics  mnemonic words
   * @param passphrase passphrase
   * @return a seed derived from the mnemonic words and passphrase
   */
  def toSeed(mnemonics: Seq[String], passphrase: String): ByteVector = ByteVector.view(fr.acinq.bitcoin.MnemonicCode.toSeed(mnemonics.asJava, passphrase))

  def toSeed(mnemonics: String, passphrase: String): ByteVector = toSeed(mnemonics.split(" ").toSeq, passphrase)
}
