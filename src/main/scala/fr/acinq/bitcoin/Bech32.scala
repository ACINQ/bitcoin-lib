package fr.acinq.bitcoin

/**
  * See https://github.com/sipa/bech32/blob/master/bip-witaddr.mediawiki
  */
object Bech32 {
  val alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

  // 5 bits integer
  // Bech32 works with 5bits values, we use this type to make it explicit: whenever you see Int5 it means 5bits values, and
  // whenever you see Byte it means 8bits values
  type Int5 = Byte

  // char -> 5 bits value
  val map: Map[Char, Int5] = alphabet.zipWithIndex.toMap.mapValues(_.toByte)
  // 5 bits value -> char
  val pam: Map[Int5, Char] = map.map(_.swap)

  def expand(hrp: String): Seq[Int5] = hrp.map(c => (c.toInt >>> 5).toByte) ++ (0.toByte +: hrp.map(c => (c.toInt & 31).toByte))

  def polymod(values: Seq[Int5]): Int = {
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

  /**
    * decodes a bech32 string
    *
    * @param bech32 bech32 string
    * @return a (hrp, data) tuple
    */
  def decode(bech32: String): (String, Seq[Int5]) = {
    val input = bech32.toLowerCase()
    val pos = input.lastIndexOf('1')
    val hrp = input.take(pos)
    val data = input.drop(pos + 1).map(c => map(c))
    val checksum = polymod(expand(hrp) ++ data)
    require(checksum == 1, s"invalid checksum for $bech32")
    (hrp, data.dropRight(6))
  }

  /**
    *
    * @param hrp  Human Readable Part
    * @param data data (a sequence of 5 bits integers)
    * @return a checksum computed over hrp and data
    */
  def checksum(hrp: String, data: Seq[Int5]): Seq[Int5] = {
    val values = expand(hrp) ++ data
    val poly = polymod(values ++ Seq(0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte)) ^ 1.toByte
    for (i <- 0 to 5) yield ((poly >>> 5 * (5 - i)) & 31).toByte
  }

  /**
    *
    * @param input a sequence of 8 bits integers
    * @return a sequence of 5 bits integers
    */
  def eight2five(input: Seq[Byte]): Seq[Int5] = {
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

  /**
    *
    * @param input a sequence of 5 bits integers
    * @return a sequence of 8 bits integers
    */
  def five2eight(input: Seq[Int5]): Seq[Byte] = {
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

  /**
    * encode a bitcoin witness address
    *
    * @param hrp            should be "bc" or "tb"
    * @param witnessVersion witness version (0 to 16, only 0 is currently defined)
    * @param data           witness program: if version is 0, either 20 bytes (P2WPKH) or 32 bytes (P2WSH)
    * @return a bech32 encoded witness address
    */
  def encodeWitnessAddress(hrp: String, witnessVersion: Byte, data: BinaryData): String = {
    // prepend witness version: 0
    val data1 = witnessVersion +: Bech32.eight2five(data)
    val checksum = Bech32.checksum(hrp, data1)
    hrp + "1" + new String((data1 ++ checksum).map(i => Bech32.pam(i)).toArray)
  }

  /**
    * decode a bitcoin witness address
    *
    * @param address witness address
    * @return a (version, program) tuple where version is the witness version and program the decoded witness program.
    *         If version is 0, it will be either 20 bytes (P2WPKH) or 32 bytes (P2WSH)
    */
  def decodeWitnessAddress(address: String): (Byte, BinaryData) = {
    if (address.indexWhere(_.isLower) != -1 && address.indexWhere(_.isUpper) != -1) throw new IllegalArgumentException("input mixes lowercase and uppercase characters")
    val (hrp, data) = decode(address)
    require(hrp == "bc" || hrp == "tb" || hrp == "bcrt", s"invalid HRP $hrp")
    val version = data(0)
    require(version >= 0 && version <= 16, "invalid segwit version")
    val bin = five2eight(data.drop(1))
    require(bin.length >= 2 && bin.length <= 40, s"invalid witness program length ${bin.length}")
    if (version == 0) require(bin.length == 20 || bin.length == 32, s"invalid witness program length ${bin.length}")
    (version, bin)
  }

}
