package fr.acinq.bitcoin

import java.math.BigInteger

object Base58 {
  val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  // char -> value
  val map = alphabet.zipWithIndex.toMap

  def encode(input: Array[Byte]): String = {
    if (input.isEmpty) ""
    else {
      val big = new BigInteger(1, input)
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
