package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.net.InetAddress
import java.util

import com.google.common.io.ByteStreams
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class ProtocolSpec extends FlatSpec {
  "Protocol" should "parse blochain blocks" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block1.dat")
    val block = Block.read(stream)
    // check that we can deserialize and re-serialize scripts
    block.tx.map(tx => {
      tx.txIn.map(txin => {
        if (!txin.outPoint.isCoinbaseOutPoint) {
          val script = Script.parse(txin.signatureScript)
          val stream = new ByteArrayOutputStream()
          Script.write(script, stream)
          val check = stream.toByteArray
          assert(java.util.Arrays.equals(txin.signatureScript, check))
        }
      })
      tx.txOut.map(txout => {
        val script = Script.parse(txout.publicKeyScript)
        val stream = new ByteArrayOutputStream()
        Script.write(script, stream)
        val check = stream.toByteArray
        assert(java.util.Arrays.equals(txout.publicKeyScript, check))
      })
    })
  }
  it should "serialize/deserialize blocks" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block1.dat")
    val bytes = ByteStreams.toByteArray(stream)
    val block = Block.read(bytes)
    val check = Block.write(block)
    assert(util.Arrays.equals(check, bytes))
  }
  it should "decode transactions" in {
    // data copied from https://people.xiph.org/~greg/signdemo.txt
    val tx = Transaction.read(new ByteArrayInputStream(fromHexString("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")))
    val script = Script.parse(tx.txOut(0).publicKeyScript)
    val publicKeyHash = Script.publicKeyHash(script)
    assert(Address.encode(0x6f, publicKeyHash) === "mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT")
  }
  it should "generate genesis block" in {
    assert(toHexString(Block.write(Block.LivenetGenesisBlock)) === "0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A29AB5F49FFFF001D1DAC2B7C0101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000".toLowerCase)
    assert(toHexString(Block.TestnetGenesisBlock.hash) === "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000")
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

    assert(toHexString(Version.write(version)) === "721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message = Message(magic = 0x0709110bL, command = "version", payload = Version.write(version))
    assert(toHexString(Message.write(message)) === "0b11090776657273696f6e0000000000660000008c48bb56721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message1 = Message.read(Message.write(message))
    assert(message1.command === "version")
    val version1 = Version.read(message1.payload)
    assert(version1 === version)
  }
  it should "read and write verack messages" in {
    val message = Message.read(fromHexString("0b11090776657261636b000000000000000000005df6e0e2"))
    assert(message.command === "verack")
    assert(message.payload.isEmpty)

    val message1 = Message(magic = 0x0709110bL, command = "verack", payload = Array.empty[Byte])
    assert(toHexString(Message.write(message1)) === "0b11090776657261636b000000000000000000005df6e0e2")
  }
  it should "read and write addr messages" in {
    // example take from https://en.bitcoin.it/wiki/Protocol_specification#addr
    val message = Message.read(fromHexString("f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d"))
    assert(message.command === "addr")
    val addr = Addr.read(message.payload)
    assert(addr.addresses.length === 1)
    assert(addr.addresses(0).address.getAddress === Array(10:Byte, 0:Byte, 0:Byte, 1:Byte))
    assert(addr.addresses(0).port === 8333)

    val addr1 = Addr(List(NetworkAddressWithTimestamp(time = 1292899810L, services = 1L, address = InetAddress.getByAddress(Array(10:Byte, 0:Byte, 0:Byte, 1:Byte)), port = 8333)))
    val message1 = Message(magic = 0xd9b4bef9, command = "addr", payload = Addr.write(addr1))
    assert(toHexString(Message.write(message1)) === "f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d")
  }
  it should "read and write inventory messages" in {
    val inventory = Inventory.read(fromHexString("01010000004d43a12ddedc1638542a4c5a5dff3fc5daa9bd543ecccbe8c7eed8648044668f"))
    assert(inventory.inventory.length === 1)
    assert(inventory.inventory(0).`type` === InventoryVector.MSG_TX)
  }
}
