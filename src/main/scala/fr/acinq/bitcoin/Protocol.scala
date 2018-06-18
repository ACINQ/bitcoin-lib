package fr.acinq.bitcoin

import java.io._
import java.net.{Inet4Address, Inet6Address, InetAddress}
import java.nio.{ByteBuffer, ByteOrder}

import scala.collection.mutable.ArrayBuffer

/**
  * see https://en.bitcoin.it/wiki/Protocol_specification
  */

object BinaryData {
  def apply(hex: String): BinaryData = hex

  val empty: BinaryData = Seq.empty[Byte]
}

case class BinaryData(data: Seq[Byte]) {
  def length = data.length

  override def toString = toHexString(data)

  override def equals(obj: scala.Any): Boolean = obj match {
    case BinaryData(someData) => data.toArray.deep == someData.data.toArray.deep
    case _                    => false
  }
}

object Protocol {
  /**
    * basic serialization functions
    */

  val PROTOCOL_VERSION = 70015

  def uint8(input: InputStream): Int = input.read()

  def writeUInt8(input: Int, out: OutputStream): Unit = out.write(input & 0xff)
  def writeUInt8(input: Int): BinaryData = Array( (input & 0xff).toByte )

  def uint16(input: InputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Int = {
    val bin = new Array[Byte](2)
    input.read(bin)
    uint16(bin, order)
  }

  def uint16(input: BinaryData, order: ByteOrder): Int = {
    val buffer = ByteBuffer.wrap(input).order(order)
    buffer.getShort & 0xFFFF
  }

  def writeUInt16(input: Int, out: OutputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Unit = out.write(writeUInt16(input, order))

  def writeUInt16(input: Int, order: ByteOrder): BinaryData = {
    val bin = new Array[Byte](2)
    val buffer = ByteBuffer.wrap(bin).order(order)
    buffer.putShort(input.toShort)
    bin
  }

  def uint32(input: InputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Long = {
    val bin = new Array[Byte](4)
    input.read(bin)
    uint32(bin, order)
  }

  def uint32(input: BinaryData, order: ByteOrder): Long = {
    val buffer = ByteBuffer.wrap(input).order(order)
    buffer.getInt() & 0xFFFFFFFFL
  }

  def writeUInt32(input: Long, out: OutputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Unit = out.write(writeUInt32(input, order))

  def writeUInt32(input: Long, order: ByteOrder): Array[Byte] = {
    val bin = new Array[Byte](4)
    val buffer = ByteBuffer.wrap(bin).order(order)
    buffer.putInt((input & 0xffffffff).toInt)
    bin
  }

  def writeUInt32(input: Long): Array[Byte] = writeUInt32(input, ByteOrder.LITTLE_ENDIAN)

  def uint64(input: InputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Long = {
    val bin = new Array[Byte](8)
    input.read(bin)
    uint64(bin, order)
  }

  def uint64(input: BinaryData, order: ByteOrder): Long = {
    val buffer = ByteBuffer.wrap(input).order(order)
    buffer.getLong()
  }

  def writeUInt64(input: Long, out: OutputStream, order: ByteOrder = ByteOrder.LITTLE_ENDIAN): Unit = out.write(writeUInt64(input, order))

  def writeUInt64(input: Long, order: ByteOrder): Array[Byte] = {
    val bin = new Array[Byte](8)
    val buffer = ByteBuffer.wrap(bin).order(order)
    buffer.putLong(input)
    bin
  }

  def varint(blob: Array[Byte]): Long = varint(new ByteArrayInputStream(blob))

  def varint(input: InputStream): Long = input.read() match {
    case value if value < 0xfd => value
    case 0xfd => uint16(input)
    case 0xfe => uint32(input)
    case 0xff => uint64(input)
  }

  def writeVarint(input: Long): BinaryData = {
    if (input < 0xfdL) {
      writeUInt8(input.toInt)
    }
    else if (input < 65535L) {
      writeUInt8(0xfd) ++ writeUInt16(input.toInt, ByteOrder.LITTLE_ENDIAN)
    }
    else if (input < 1048576L) {
      writeUInt8(0xfe) ++ writeUInt32(input.toInt)
    }
    else {
      writeUInt8(0xff) ++ writeUInt64(input, ByteOrder.LITTLE_ENDIAN)
    }
  }

  def writeVarint(input: Int, out: OutputStream): Unit = writeVarint(input.toLong, out)

  def writeVarint(input: Long, out: OutputStream): Unit = out.write(writeVarint(input))

  def bytes(input: InputStream, size: Long): BinaryData = bytes(input, size.toInt)

  def bytes(input: InputStream, size: Int): BinaryData = {
    val blob = new Array[Byte](size)
    if (size > 0) {
      val count = input.read(blob)
      if (count < size) throw new IOException("not enough data to read from")
    }
    blob
  }

  def writeBytes(input: Array[Byte], out: OutputStream): Unit = out.write(input)

  def varstring(input: InputStream): String = {
    val length = varint(input)
    new String(bytes(input, length), "UTF-8")
  }

  def writeVarstring(input: String, out: OutputStream) = {
    writeVarint(input.length, out)
    writeBytes(input.getBytes("UTF-8"), out)
  }

  def hash(input: InputStream): BinaryData = bytes(input, 32) // a hash is always 256 bits

  def script(input: InputStream): BinaryData = {
    val length = varint(input) // read size
    bytes(input, length.toInt) // read bytes
  }

  def writeScript(input: Array[Byte], out: OutputStream): Unit = {
    writeVarint(input.length.toLong, out)
    writeBytes(input, out)
  }

  implicit val txInSer = TxIn
  implicit val txOutSer = TxOut
  implicit val scriptWitnessSer = ScriptWitness
  implicit val txSer = Transaction
  implicit val networkAddressWithTimestampSer = NetworkAddressWithTimestamp
  implicit val inventoryVectorOutSer = InventoryVector

  def readCollection[T](input: InputStream, maxElement: Option[Int], protocolVersion: Long)(implicit ser: BtcSerializer[T]): Seq[T] =
    readCollection(input, ser.read, maxElement, protocolVersion)

  def readCollection[T](input: InputStream, protocolVersion: Long)(implicit ser: BtcSerializer[T]): Seq[T] =
    readCollection(input, None, protocolVersion)(ser)

  def readCollection[T](input: InputStream, reader: (InputStream, Long) => T, maxElement: Option[Int], protocolVersion: Long): Seq[T] = {
    val count = varint(input)
    maxElement.foreach(max => require(count <= max, "invalid length"))
    val items = ArrayBuffer.empty[T]
    for (_ <- 1L to count) {
      items += reader(input, protocolVersion)
    }
    items
  }

  def readCollection[T](input: InputStream, reader: (InputStream, Long) => T, protocolVersion: Long): Seq[T] = readCollection(input, reader, None, protocolVersion)

  def writeCollection[T](seq: Seq[T], out: OutputStream, protocolVersion: Long)(implicit ser: BtcSerializer[T]): Unit = {
    writeVarint(seq.length, out)
    seq.foreach(t => ser.write(t, out, protocolVersion))
  }

  def writeCollection[T](seq: Seq[T], writer: (T, OutputStream, Long) => Unit, out: OutputStream, protocolVersion: Long): Unit = {
    writeVarint(seq.length, out)
    seq.foreach(t => writer(t, out, protocolVersion))
  }
}

import fr.acinq.bitcoin.Protocol._

trait BtcSerializer[T] {
  /**
    * write a message to a stream
    *
    * @param t   message
    * @param out output stream
    */
  def write(t: T, out: OutputStream, protocolVersion: Long): Unit

  def write(t: T, out: OutputStream): Unit = write(t, out, PROTOCOL_VERSION)

  /**
    * write a message to a byte array
    *
    * @param t message
    * @return a serialized message
    */
  def write(t: T, protocolVersion: Long): BinaryData = {
    val out = new ByteArrayOutputStream()
    write(t, out, protocolVersion)
    out.toByteArray
  }

  def write(t: T): BinaryData = write(t, PROTOCOL_VERSION)

  /**
    * read a message from a stream
    *
    * @param in input stream
    * @return a deserialized message
    */
  def read(in: InputStream, protocolVersion: Long): T

  def read(in: InputStream): T = read(in, PROTOCOL_VERSION)

  /**
    * read a message from a byte array
    *
    * @param in serialized message
    * @return a deserialized message
    */
  def read(in: Seq[Byte], protocolVersion: Long): T = read(new ByteArrayInputStream(in.toArray), protocolVersion)

  def read(in: Seq[Byte]): T = read(in, PROTOCOL_VERSION)

  /**
    * read a message from a hex string
    *
    * @param in message binary data in hex format
    * @return a deserialized message of type T
    */
  def read(in: String, protocolVersion: Long): T = read(fromHexString(in), protocolVersion)

  def read(in: String): T = read(in, PROTOCOL_VERSION)

  def validate(t: T): Unit = {}
}

trait BtcSerializable[T] {
  def serializer: BtcSerializer[T]
}

object Message extends BtcSerializer[Message] {
  val MagicMain = 0xD9B4BEF9L
  val MagicTestNet = 0xDAB5BFFAL
  val MagicTestnet3 = 0x0709110BL
  val MagicNamecoin = 0xFEB4BEF9L
  val MagicSegnet = 0xC4A1ABDC

  override def read(in: InputStream, protocolVersion: Long): Message = {
    val magic = uint32(in)
    val buffer = new Array[Byte](12)
    in.read(buffer)
    val buffer1 = buffer.takeWhile(_ != 0)
    val command = new String(buffer1, "ISO-8859-1")
    val length = uint32(in)
    require(length < 2000000, "invalid payload length")
    val checksum = uint32(in)
    val payload = new Array[Byte](length.toInt)
    in.read(payload)
    require(checksum == uint32(new ByteArrayInputStream(Crypto.hash256(payload).take(4).toArray)), "invalid checksum")
    Message(magic, command, payload)
  }

  override def write(input: Message, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.magic.toInt, out)
    val buffer = new Array[Byte](12)
    input.command.getBytes("ISO-8859-1").copyToArray(buffer)
    writeBytes(buffer, out)
    writeUInt32(input.payload.length, out)
    val checksum = Crypto.hash256(input.payload).take(4).toArray
    writeBytes(checksum, out)
    writeBytes(input.payload, out)
  }
}

/**
  * Bitcoin message exchanged by nodes over the network
  *
  * @param magic   Magic value indicating message origin network, and used to seek to next message when stream state is unknown
  * @param command ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
  * @param payload The actual data
  */
case class Message(magic: Long, command: String, payload: BinaryData) extends BtcSerializable[Message] {
  require(command.length <= 12)

  override def serializer: BtcSerializer[Message] = Message
}

object NetworkAddressWithTimestamp extends BtcSerializer[NetworkAddressWithTimestamp] {
  override def read(in: InputStream, protocolVersion: Long): NetworkAddressWithTimestamp = {
    val time = uint32(in)
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    val address = InetAddress.getByAddress(raw)
    val port = uint16(in, ByteOrder.BIG_ENDIAN)
    NetworkAddressWithTimestamp(time, services, address, port)
  }

  override def write(input: NetworkAddressWithTimestamp, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.time.toInt, out)
    writeUInt64(input.services, out)
    input.address match {
      case _: Inet4Address => writeBytes(fromHexString("00000000000000000000ffff"), out)
      case _: Inet6Address => ()
    }
    writeBytes(input.address.getAddress, out)
    writeUInt16(input.port.toInt, out, ByteOrder.BIG_ENDIAN)
  }
}

case class NetworkAddressWithTimestamp(time: Long, services: Long, address: InetAddress, port: Long) extends BtcSerializable[NetworkAddressWithTimestamp] {
  override def serializer: BtcSerializer[NetworkAddressWithTimestamp] = NetworkAddressWithTimestamp
}

object NetworkAddress extends BtcSerializer[NetworkAddress] {
  override def read(in: InputStream, protocolVersion: Long): NetworkAddress = {
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    val address = InetAddress.getByAddress(raw)
    val port = uint16(in, ByteOrder.BIG_ENDIAN)
    NetworkAddress(services, address, port)
  }

  override def write(input: NetworkAddress, out: OutputStream, protocolVersion: Long) = {
    writeUInt64(input.services, out)
    input.address match {
      case _: Inet4Address => writeBytes(fromHexString("00000000000000000000ffff"), out)
      case _: Inet6Address => ()
    }
    writeBytes(input.address.getAddress, out)
    writeUInt16(input.port.toInt, out, ByteOrder.BIG_ENDIAN) // wtf ?? why BE there ?
  }
}

case class NetworkAddress(services: Long, address: InetAddress, port: Long) extends BtcSerializable[NetworkAddress] {
  override def serializer: BtcSerializer[NetworkAddress] = NetworkAddress
}

object Version extends BtcSerializer[Version] {
  override def read(in: InputStream, protocolVersion: Long): Version = {
    val version = uint32(in)
    val services = uint64(in)
    val timestamp = uint64(in)
    val addr_recv = NetworkAddress.read(in)
    val addr_from = NetworkAddress.read(in)
    val nonce = uint64(in)
    val length = varint(in)
    val buffer = bytes(in, length)
    val user_agent = new String(buffer, "ISO-8859-1")
    val start_height = uint32(in)
    val relay = if (uint8(in) == 0) false else true
    Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay)
  }

  override def write(input: Version, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.version.toInt, out)
    writeUInt64(input.services, out)
    writeUInt64(input.timestamp, out)
    NetworkAddress.write(input.addr_recv, out)
    NetworkAddress.write(input.addr_from, out)
    writeUInt64(input.nonce, out)
    writeVarint(input.user_agent.length, out)
    writeBytes(input.user_agent.getBytes("ISO-8859-1"), out)
    writeUInt32(input.start_height.toInt, out)
    writeUInt8(if (input.relay) 1 else 0, out)
  }
}

/**
  *
  * @param version      Identifies protocol version being used by the node
  * @param services     bitfield of features to be enabled for this connection
  * @param timestamp    standard UNIX timestamp in seconds
  * @param addr_recv    The network address of the node receiving this message
  * @param addr_from    The network address of the node emitting this message
  * @param nonce        Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect
  *                     connections to self.
  * @param user_agent   User Agent
  * @param start_height The last block received by the emitting node
  * @param relay        Whether the remote peer should announce relayed transactions or not, see BIP 0037,
  *                     since version >= 70001
  */
case class Version(version: Long, services: Long, timestamp: Long, addr_recv: NetworkAddress, addr_from: NetworkAddress, nonce: Long, user_agent: String, start_height: Long, relay: Boolean) extends BtcSerializable[Version] {
  override def serializer: BtcSerializer[Version] = Version
}

object Addr extends BtcSerializer[Addr] {
  override def write(t: Addr, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.addresses, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Addr =
    Addr(readCollection[NetworkAddressWithTimestamp](in, Some(1000), protocolVersion))
}

case class Addr(addresses: Seq[NetworkAddressWithTimestamp]) extends BtcSerializable[Addr] {
  override def serializer: BtcSerializer[Addr] = Addr
}

object InventoryVector extends BtcSerializer[InventoryVector] {
  val ERROR = 0L
  val MSG_TX = 1L
  val MSG_BLOCK = 2L

  override def write(t: InventoryVector, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.`type`.toInt, out)
    writeBytes(t.hash, out)
  }

  override def read(in: InputStream, protocolVersion: Long): InventoryVector = InventoryVector(uint32(in), hash(in))
}

case class InventoryVector(`type`: Long, hash: BinaryData) extends BtcSerializable[InventoryVector] {
  require(hash.length == 32, "invalid hash length")

  override def serializer: BtcSerializer[InventoryVector] = InventoryVector
}

object Inventory extends BtcSerializer[Inventory] {
  override def write(t: Inventory, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.inventory, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Inventory = Inventory(readCollection[InventoryVector](in, Some(1000), protocolVersion))
}

case class Inventory(inventory: Seq[InventoryVector]) extends BtcSerializable[Inventory] {
  override def serializer: BtcSerializer[Inventory] = Inventory
}

object Getheaders extends BtcSerializer[Getheaders] {
  override def write(t: Getheaders, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.version.toInt, out)
    writeCollection(t.locatorHashes, (h: BinaryData, o: OutputStream, _: Long) => o.write(h), out, protocolVersion)
    writeBytes(t.stopHash, out)
  }

  override def read(in: InputStream, protocolVersion: Long): Getheaders = {
    Getheaders(version = uint32(in), locatorHashes = readCollection[BinaryData](in, (i: InputStream, _: Long) => BinaryData(hash(i)), protocolVersion), stopHash = hash(in))
  }
}

case class Getheaders(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) extends BtcSerializable[Getheaders] {
  locatorHashes.foreach(h => require(h.length == 32))
  require(stopHash.length == 32)

  override def serializer: BtcSerializer[Getheaders] = Getheaders
}

object Headers extends BtcSerializer[Headers] {
  override def write(t: Headers, out: OutputStream, protocolVersion: Long): Unit = {
    writeCollection(t.headers, (t: BlockHeader, o: OutputStream, v: Long) => {
      BlockHeader.write(t, o, v)
      writeVarint(0, o)
    }, out, protocolVersion)
  }

  override def read(in: InputStream, protocolVersion: Long): Headers = {
    Headers(readCollection(in, (i: InputStream, v: Long) => {
      val header = BlockHeader.read(i, v)
      val dummy = varint(in)
      require(dummy == 0, s"header in headers message ends with $dummy, should be 0 instead")
      header
    }, protocolVersion))
  }
}

case class Headers(headers: Seq[BlockHeader]) extends BtcSerializable[Headers] {
  override def serializer: BtcSerializer[Headers] = Headers
}

object Getblocks extends BtcSerializer[Getblocks] {
  override def write(t: Getblocks, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.version.toInt, out)
    writeCollection(t.locatorHashes, (h: BinaryData, o: OutputStream, _: Long) => o.write(h), out, protocolVersion)
    writeBytes(t.stopHash, out)
  }

  override def read(in: InputStream, protocolVersion: Long): Getblocks = {
    Getblocks(version = uint32(in), locatorHashes = readCollection(in, (i: InputStream, _: Long) => BinaryData(hash(i)), protocolVersion), stopHash = hash(in))
  }
}

case class Getblocks(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) extends BtcSerializable[Getblocks] {
  locatorHashes.foreach(h => require(h.length == 32))
  require(stopHash.length == 32)

  override def serializer: BtcSerializer[Getblocks] = Getblocks
}

object Getdata extends BtcSerializer[Getdata] {
  override def write(t: Getdata, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.inventory, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Getdata = Getdata(readCollection[InventoryVector](in, protocolVersion))
}

case class Getdata(inventory: Seq[InventoryVector]) extends BtcSerializable[Getdata] {
  override def serializer: BtcSerializer[Getdata] = Getdata
}

object Reject extends BtcSerializer[Reject] {
  override def write(t: Reject, out: OutputStream, protocolVersion: Long): Unit = {
    writeVarstring(t.message, out)
    writeUInt8(t.code.toInt, out)
    writeVarstring(t.reason, out)
  }

  override def read(in: InputStream, protocolVersion: Long): Reject = {
    Reject(message = varstring(in), code = uint8(in), reason = varstring(in), Array.empty[Byte])
  }
}

case class Reject(message: String, code: Long, reason: String, data: BinaryData) extends BtcSerializable[Reject] {
  override def serializer: BtcSerializer[Reject] = Reject
}