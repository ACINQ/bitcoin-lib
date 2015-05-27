package fr.acinq.bitcoin

import java.math.BigInteger
import java.util

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
  def decode(input: String) : Array[Byte] = {
    def decode1(in: List[Char], current: BigInteger = BigInteger.ZERO) : BigInteger = in match {
      case Nil => current
      case head :: tail => decode1(tail, current.multiply(BigInteger.valueOf(58L)).add(BigInteger.valueOf(map(head).toLong)))
    }
    val zeroes = input.takeWhile(_ == '1').map(_ => 0:Byte).toArray
    val trim  = input.dropWhile(_ == '1').toList
    val decoded = decode1(trim).toByteArray.dropWhile(_ == 0) // BigInteger.toByteArray may add a leading 0x00
    if (trim.isEmpty) zeroes else zeroes ++ decoded
  }
}

object Base58Check {
  def checksum(data: Seq[Byte]) = Crypto.hash256(data).take(4)

  def encode(version: Byte, data: Seq[Byte]) : String = {
    val versionAndData = version +: data
    Base58.encode(versionAndData ++ checksum(versionAndData))
  }

  def decode(encoded: String) : (Byte, Array[Byte]) = {
    val raw = Base58.decode(encoded)
    val versionAndHash = raw.dropRight(4)
    val checksum = raw.takeRight(4)
    if (!util.Arrays.equals(checksum, Base58Check.checksum(versionAndHash))) {
      throw new RuntimeException(s"invalid Base58Check data $encoded")
    }
    (versionAndHash(0), versionAndHash.tail)
  }
}