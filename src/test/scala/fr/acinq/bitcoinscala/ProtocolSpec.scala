package fr.acinq.bitcoinscala

import java.math.BigInteger
import java.net.InetAddress

import com.google.common.io.ByteStreams
import org.scalatest.FlatSpec
import scodec.bits._

class ProtocolSpec extends FlatSpec {
  it should "decode transactions" in {
    // data copied from https://people.xiph.org/~greg/signdemo.txt
    val tx = Transaction.read("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")
    val script = Script.parse(tx.txOut(0).publicKeyScript)
    val publicKeyHash = Script.publicKeyHash(script)
    assert(Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKeyHash) === "mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT")
  }
  it should "decode proof-of-work difficulty" in {
    assert(decodeCompact(0) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x00123456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01003456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x02000056) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x03000000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x04000000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x00923456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01803456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x02800056) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x03800000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x04800000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01123456) === (BigInteger.valueOf(0x12), false, false))
    assert(decodeCompact(0x01fedcba) === (BigInteger.valueOf(0x7e), true, false))
    assert(decodeCompact(0x02123456) === (BigInteger.valueOf(0x1234), false, false))
    assert(decodeCompact(0x03123456) === (BigInteger.valueOf(0x123456), false, false))
    assert(decodeCompact(0x04123456) === (BigInteger.valueOf(0x12345600), false, false))
    assert(decodeCompact(0x04923456) === (BigInteger.valueOf(0x12345600), true, false))
    assert(decodeCompact(0x05009234) === (new BigInteger(1, hex"92340000".toArray), false, false))
    assert(decodeCompact(0x20123456) === (new BigInteger(1, hex"1234560000000000000000000000000000000000000000000000000000000000".toArray), false, false))
    val (_, false, true) = decodeCompact(0xff123456L)
  }
  it should "read and write version messages" in {
    val version = Version(
      0x00011172L,
      services = 1L,
      timestamp = 0x53c420c4L,
      addr_recv = NetworkAddress(1L, InetAddress.getByAddress(Array(85.toByte, 235.toByte, 17.toByte, 3.toByte)), 18333L),
      addr_from = NetworkAddress(1L, InetAddress.getByAddress(Array(109.toByte, 24.toByte, 186.toByte, 185.toByte)), 18333L),
      nonce = 0x4317be39ae6ea291L,
      user_agent = "/Satoshi:0.9.99/",
      start_height = 0x00041a23L,
      relay = true)

    assert(Version.write(version) === hex"721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message = Message(magic = 0x0709110bL, command = "version", payload = Version.write(version))
    assert(Message.write(message) === hex"0b11090776657273696f6e0000000000660000008c48bb56721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message1 = Message.read(Message.write(message).toArray)
    assert(message1.command === "version")
    val version1 = Version.read(message1.payload.toArray)
    assert(version1 === version)
  }
  it should "read and write verack messages" in {
    val message = Message.read("0b11090776657261636b000000000000000000005df6e0e2")
    assert(message.command === "verack")
    assert(message.payload.isEmpty)

    val message1 = Message(magic = 0x0709110bL, command = "verack", payload = ByteVector.empty)
    assert(Message.write(message1) === hex"0b11090776657261636b000000000000000000005df6e0e2")
  }
  it should "read and write addr messages" in {
    // example take from https://en.bitcoin.it/wiki/Protocol_specification#addr
    val message = Message.read("f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d")
    assert(message.command === "addr")
    val addr = Addr.read(message.payload.toArray)
    assert(addr.addresses.length === 1)
    assert(addr.addresses(0).address.getAddress === Array(10: Byte, 0: Byte, 0: Byte, 1: Byte))
    assert(addr.addresses(0).port === 8333)

    val addr1 = Addr(List(NetworkAddressWithTimestamp(time = 1292899810L, services = 1L, address = InetAddress.getByAddress(Array(10: Byte, 0: Byte, 0: Byte, 1: Byte)), port = 8333)))
    val message1 = Message(magic = 0xd9b4bef9, command = "addr", payload = Addr.write(addr1))
    assert(Message.write(message1) === hex"f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d")
  }
  it should "read and write addr messages 2" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/addr.dat")
    val message = Message.read(stream)
    assert(message.command === "addr")
    val addr = Addr.read(message.payload.toArray)
    assert(addr.addresses.length === 1000)
  }
  it should "read and write inventory messages" in {
    val inventory = Inventory.read("01010000004d43a12ddedc1638542a4c5a5dff3fc5daa9bd543ecccbe8c7eed8648044668f")
    assert(inventory.inventory.length === 1)
    assert(inventory.inventory(0).`type` === InventoryVector.MSG_TX)
  }
  it should "read and write inventory messages 2" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/inv.dat")
    val message = Message.read(stream)
    assert(message.command === "inv")
    val inv = Inventory.read(message.payload.toArray)
    assert(inv.inventory.size === 500)
    assert(message.payload == Inventory.write(inv))
  }
  it should "read and write getblocks messages" in {
    val message = Message.read("f9beb4d9676574626c6f636b7300000045000000f5fcbcad72110100016fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000")
    assert(message.command == "getblocks")
    val getblocks = Getblocks.read(message.payload.toArray)
    assert(getblocks.version === 70002)
    assert(getblocks.locatorHashes.head === hex"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
    assert(Getblocks.write(getblocks) === message.payload)
  }
  it should "read and write getheaders message" in {
    val getheaders = Getheaders.read("711101000106226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000000000000000000000000000000000000000000000000000000000000000")
    assert(getheaders.locatorHashes(0) === Block.RegtestGenesisBlock.hash)
    assert(Getheaders.write(getheaders) === hex"711101000106226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000000000000000000000000000000000000000000000000000000000000000")
  }
  it should "read and write getdata messages" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/getdata.dat")
    val message = Message.read(stream)
    assert(message.command === "getdata")
    val getdata = Getdata.read(message.payload.toArray)
    assert(getdata.inventory.size === 128)
    assert(getdata.inventory(0).hash === hex"4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000")
    val check = Getdata.write(getdata)
    assert(check == message.payload)
  }
  it should "read and write reject messages" in {
    val message = Message.read("0b11090772656a6563740000000000001f00000051e3a01d076765746461746101156572726f722070617273696e67206d657373616765")
    assert(message.command === "reject")
    val reject = Reject.read(message.payload.toArray)
    assert(reject.message === "getdata")
    assert(Reject.write(reject) == message.payload)
  }
}
