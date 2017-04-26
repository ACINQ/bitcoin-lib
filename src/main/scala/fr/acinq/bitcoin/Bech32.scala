package fr.acinq.bitcoin

/**
  * Created by fabrice on 19/04/17.
  */
object Bech32 {
  val alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  val map = alphabet.zipWithIndex.toMap
  val pam = map.map(_.swap)

  def expand(hrp: String): Seq[Byte] = hrp.map(c => (c.toInt >>> 5).toByte) ++ (0.toByte +: hrp.map(c => (c.toInt & 31).toByte))

  def polymod(values: Seq[Byte]): Int = {
    val GEN = Seq(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    var chk = 1
    values.map(v => {
      val b = chk >>> 25
      chk = ((chk & 0x1ffffff) << 5) ^ v
      for (i <- 0 until 5) {
        if (((b >>> i) & 1) != 0) chk = chk ^ GEN(i)
      }
    })
    chk
  }

  def decode(input1: String): (String, Seq[Byte]) = {
    val input = input1.toLowerCase()
    val pos = input.lastIndexOf('1')
    val hrp = input.take(pos)
    val data = input.drop(pos + 1).map(c => map(c).toByte)
    val checksum = polymod(expand(hrp) ++ data)
    require(checksum == 1, s"invalid checksum for $input1")
    (hrp, data.dropRight(6))
  }

  def checksum(hrp: String, data : Seq[Byte]): Seq[Byte] = {
    val values = expand(hrp) ++ data
    val poly = polymod(values ++ Seq(0.toByte,0.toByte,0.toByte,0.toByte,0.toByte,0.toByte)) ^ 1.toByte
    for(i <- 0 to 5) yield ((poly >>> 5 * (5 - i)) & 31).toByte
  }

  def eight2five(input: Seq[Byte]): Seq[Byte] = {
    var buffer = 0L
    val output = collection.mutable.ArrayBuffer.empty[Byte]
    var count = 0
    input.map(b => {
      buffer = (buffer << 8) | (b & 0xff)
      count = count + 8
      while (count >= 5) {
        output.append(((buffer >> (count - 5)) & 31).toByte)
        count = count - 5
      }
    })
    if (count > 0) output.append(((buffer << (5 - count)) & 31).toByte)
    output
  }

  def five2eight(input: Seq[Byte]): Seq[Byte] = {
    var buffer = 0L
    val output = collection.mutable.ArrayBuffer.empty[Byte]
    var count = 0
    input.map(b => {
      buffer = (buffer << 5) | (b & 31)
      count = count + 5
      while (count >= 8) {
        output.append(((buffer >> (count - 8)) & 0xff).toByte)
        count = count - 8
      }
    })
    require(count <= 4, "Zero-padding of more than 4 bits")
    require((buffer & ((1 << count) - 1)) == 0, "Non-zero padding in 8-to-5 conversion")
    output
  }

  def encodeAddress(hrp: String, data: BinaryData) : String = {
    // prepend witness version: 0
    val data1 = 0.toByte +: Bech32.eight2five(data)
    val checksum = Bech32.checksum(hrp, data1)
    hrp + "1" + new String((data1 ++ checksum).map(i => Bech32.pam(i)).toArray)
  }

  def decodeAddress(address: String): BinaryData = {
    if (address.indexWhere(_.isLower) != -1 && address.indexWhere(_.isUpper) != -1) throw new IllegalArgumentException("input mixes lowercase and uppercase characters")
    val (hrp, data) = decode(address)
    require(hrp == "bc" || hrp == "tb", s"invalid HRP $hrp")
    require(data(0) >= 0 && data(0) <= 16, "invalid segwit version")
    val bin = five2eight(data.drop(1))
    require(bin.length >= 2 && bin.length <= 40, s"invalid witness program length ${bin.length}")
    if (data(0) == 0) require(bin.length == 20 || bin.length == 32, s"invalid witness program length ${bin.length}")
    bin
  }

}
