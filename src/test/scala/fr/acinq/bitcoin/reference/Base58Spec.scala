package fr.acinq.bitcoin.reference

import java.io.InputStreamReader

import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization
import org.scalatest.FlatSpec
import scodec.bits.ByteVector

class Base58Spec extends FlatSpec {

  implicit val format = DefaultFormats

  def resourceStream(resource: String) = classOf[Base58Spec].getResourceAsStream(resource)

  def resourceReader(resource: String) = new InputStreamReader(resourceStream(resource))

  "Base58" should "pass reference client encode/decode tests" in {
    val data = Serialization.read[List[List[String]]](resourceReader("/data/base58_encode_decode.json"))
    data.map(_ match {
      case hex :: base58 :: Nil =>
        assert(ByteVector.fromValidHex(hex) === ByteVector.fromValidBase58(base58))
        assert(ByteVector.fromValidHex(hex).toBase58 === base58)
      case unexpected =>
        println(s"wasn't expecting $unexpected")
    })
  }
}
