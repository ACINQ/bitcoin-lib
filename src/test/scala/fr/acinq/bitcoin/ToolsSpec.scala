package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream

import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class ToolsSpec extends FlatSpec {
  "Tools" should "read/write uint8" in {
    val value = 155L
    val out = new ByteArrayOutputStream()
    writeUInt8(value, out)
    assert(uint8(out.toByteArray) === value)
  }
  it should "read/write uint16" in {
    val value = 1550L
    val out = new ByteArrayOutputStream()
    writeUInt16(value, out)
    assert(uint16(out.toByteArray) === value)
  }
  it should "read/write varint" in {
    val value = 155550L
    val out = new ByteArrayOutputStream()
    writeVarint(value, out)
    assert(varint(out.toByteArray) === value)
  }
}
