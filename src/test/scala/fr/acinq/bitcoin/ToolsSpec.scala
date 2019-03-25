package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}

import fr.acinq.bitcoin.Protocol._
import org.scalatest.FlatSpec

class ToolsSpec extends FlatSpec {
  "Tools" should "read/write uint8" in {
    Seq(0, 15, 155, 0xee, 0xff).map(value => {
      val out = new ByteArrayOutputStream()
      writeUInt8(value, out)
      assert(uint8(new ByteArrayInputStream(out.toByteArray)) === value)
    })
  }
  it should "read/write uint16" in {
    Seq(0, 15, 1550, 0xa0f1, 0xfef1, 0xffff).map(value => {
      val out = new ByteArrayOutputStream()
      writeUInt16(value, out)
      assert(uint16(new ByteArrayInputStream(out.toByteArray)) === value)
    })
  }
  it should "read/write uint32" in {
    Seq(0, 15, 1550, 0xa0f1, 0xfef1, 0xffff, 0x00000000, 0x00000001, 0x10000000L, 0xaef5ff86L, 0xfeffaf05L, 0xffffffL).map(value => {
      val out = new ByteArrayOutputStream()
      writeUInt32(value, out)
      assert(uint32(new ByteArrayInputStream(out.toByteArray)) === value)
    })
  }
  it should "read/write uint64" in {
    Seq(0, 15, 1550, 0xa0f1, 0xfef1, 0xffff, 0x00000000, 0x00000001, 0x10000000L, 0xaef5ff86L, 0xfeffaf05L, 0xffffffL, 0x1000000000000000L, 0xFFFFFFFFFFFFFFFFL).map(value => {
      val out = new ByteArrayOutputStream()
      writeUInt64(value, out)
      assert(uint64(new ByteArrayInputStream(out.toByteArray)) === value)
    })
  }
  it should "read/write varint" in {
    val value = 155550L
    val out = new ByteArrayOutputStream()
    writeVarint(value, out)
    assert(varint(out.toByteArray) === value)
  }
}
