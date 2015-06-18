package fr.acinq.bitcoin

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

import scala.annotation.tailrec
import scala.io.Source

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */
object MnemonicCode {
  lazy val englishWordlist = {
    val stream = MnemonicCode.getClass.getResourceAsStream("/bip39_english_wordlist.txt")
    Source.fromInputStream(stream, "UTF-8").getLines().toSeq
  }

  private def toBinary(x: Byte): List[Boolean] = {
    @tailrec
    def loop(x: Int, acc: List[Boolean] = List.empty[Boolean]): List[Boolean] = if (x == 0) acc else loop(x / 2, ((x % 2) != 0) :: acc)

    val digits = loop(x & 0xff)
    val zeroes = List.fill(8 - digits.length)(false)
    zeroes ++ digits
  }

  private def toBinary(x: Seq[Byte]): List[Boolean] = x.map(toBinary).flatten.toList

  private def fromBinary(bin: Seq[Boolean]): Int = {
    @tailrec
    def loop(bin: Seq[Boolean], acc: Int): Int = bin match {
      case Nil => acc
      case head :: tail => loop(tail, if (head) 2 * acc + 1 else 2 * acc)
    }
    loop(bin, 0)
  }

  /**
   * BIP39 entropy encoding
   * @param entropy input entropy
   * @param wordlist word list (must be 2048 words long)
   * @return a list of mnemonic words that encodes the input entropy
   */
  def toMnemonics(entropy: Seq[Byte], wordlist: Seq[String] = englishWordlist): List[String] = {
    require(wordlist.length == 2048, "invalid word list (size should be 2048)")
    val digits = toBinary(entropy) ++ toBinary(Crypto.sha256(entropy)).take(entropy.length / 4)
    digits.grouped(11).map(fromBinary).map(index => wordlist(index)).toList
  }

  /**
   * BIP39 seed derivation
   * @param mnemonics mnemonic words
   * @param passphrase passphrase
   * @return a seed derived from the mnemonic words and passphrase
   */
  def toSeed(mnemonics: Seq[String], passphrase: String): Seq[Byte] = {
    val gen = new PKCS5S2ParametersGenerator(new SHA512Digest())
    gen.init(mnemonics.mkString(" ").getBytes("UTF-8"), ("mnemonic" + passphrase).getBytes("UTF-8"), 2048)
    val keyParams = gen.generateDerivedParameters(512).asInstanceOf[KeyParameter]
    keyParams.getKey
  }
}
