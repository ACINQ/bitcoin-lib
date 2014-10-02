package fr.acinq

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, InputStream, OutputStream}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */
package object bitcoin {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney = 21000000 * Coin
  val MaxScriptElementSize = 520

  def uint8(blob: Array[Byte]) = blob(0) & 0xffl

  def uint8(input: InputStream): Long = input.read().toLong

  def writeUInt8(input: Long, out: OutputStream): Unit = out.write((input & 0xff).asInstanceOf[Int])

  def writeUInt8(input: Int, out: OutputStream): Unit = writeUInt8(input.toLong, out)

  def writeUInt8(input: Int): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    writeUInt8(input, out)
    out.toByteArray
  }

  def uint16(a: Int, b: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8)

  def uint16BigEndian(a: Int, b: Int): Long = ((b & 0xffl) << 0) | ((a & 0xffl) << 8)

  def uint16(blob: Array[Byte]): Long = uint16(blob(0), blob(1))

  def uint16BigEndian(blob: Array[Byte]): Long = uint16BigEndian(blob(0), blob(1))

  def uint16(input: InputStream): Long = uint16(input.read(), input.read())

  def uint16BigEndian(input: InputStream): Long = uint16BigEndian(input.read(), input.read())

  def writeUInt16(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >> 8) & 0xff, out)
  }

  def writeUInt16BigEndian(input: Long, out: OutputStream): Unit = {
    writeUInt8((input >> 8) & 0xff, out)
    writeUInt8((input) & 0xff, out)
  }

  def writeUInt16(input: Int, out: OutputStream): Unit = writeUInt16(input.toLong, out)

  def uint32(a: Int, b: Int, c: Int, d: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8) | ((c & 0xffl) << 16) | ((d & 0xffl) << 24)

  def uint32(blob: Array[Byte]): Long = uint32(blob(0), blob(1), blob(2), blob(3))

  def uint32(input: InputStream): Long = {
    val blob = new Array[Byte](4)
    input.read(blob)
    uint32(blob)
  }

  def writeUInt32(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 24) & 0xff, out)
  }

  def writeUInt32(input: Int, out: OutputStream): Unit = writeUInt32(input.toLong, out)

  def writeUInt32(input: Int): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    writeUInt32(input, out)
    out.toByteArray
  }

  def writeUInt32(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(4)
    writeUInt32(input, out)
    out.toByteArray
  }

  def writeUInt32BigEndian(input: Long, out: OutputStream): Unit = {
    writeUInt8((input >>> 24) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input) & 0xff, out)
  }

  def writeUInt32BigEndian(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(4)
    writeUInt32BigEndian(input, out)
    out.toByteArray
  }

  def writeUInt32BigEndian(input: Int): Array[Byte] = writeUInt32BigEndian(input.toLong)

  def uint64(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8) | ((c & 0xffl) << 16) | ((d & 0xffl) << 24) | ((e & 0xffl) << 32) | ((f & 0xffl) << 40) | ((g & 0xffl) << 48) | ((h & 0xffl) << 56)

  def uint64(blob: Array[Byte]): Long = uint64(blob(0), blob(1), blob(2), blob(3), blob(4), blob(5), blob(6), blob(7))

  def uint64(input: InputStream): Long = uint64(input.read(), input.read(), input.read(), input.read(), input.read(), input.read(), input.read(), input.read())

  def writeUInt64(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 24) & 0xff, out)
    writeUInt8((input >>> 32) & 0xff, out)
    writeUInt8((input >>> 40) & 0xff, out)
    writeUInt8((input >>> 48) & 0xff, out)
    writeUInt8((input >>> 56) & 0xff, out)
  }

  def writeUInt64(input: Int, out: OutputStream): Unit = writeUInt64(input.toLong, out)

  def varint(blob: Array[Byte]): Long = varint(new ByteArrayInputStream(blob))

  def varint(input: InputStream): Long = input.read() match {
    case value if value < 0xfd => value
    case 0xfd => uint16(input)
    case 0xfe => uint32(input)
    case 0xff => uint64(input)
  }

  def writeVarint(input: Int, out: OutputStream): Unit = writeVarint(input.toLong, out)

  def writeVarint(input: Long, out: OutputStream): Unit = {
    if (input < 0xfdL) writeUInt8(input, out)
    else if (input < 65535L) {
      writeUInt8(0xfdL, out)
      writeUInt16(input, out)
    }
    else if (input < 1048576L) {
      writeUInt8(0xfeL, out)
      writeUInt32(input, out)
    }
    else {
      writeUInt8(0xffL, out)
      writeUInt64(input, out)
    }
  }

  def bytes(input: InputStream, size: Long): Array[Byte] = bytes(input, size.toInt)

  def bytes(input: InputStream, size: Int): Array[Byte] = {
    val blob = new Array[Byte](size)
    input.read(blob)
    blob
  }

  def hash(input: InputStream): Array[Byte] = bytes(input, 32) // a hash is always 256 bits

  def script(input: InputStream): Array[Byte] = {
    val length = varint(input) // read size
    bytes(input, length.toInt) // read bytes
  }

  def writeScript(input: Array[Byte], out: OutputStream) = {
    writeVarint(input.length.toLong, out)
    out.write(input)
  }

  def toHexString(blob: Array[Byte]) = blob.map("%02x".format(_)).mkString

  def fromHexString(hex: String): Array[Byte] = hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
}
