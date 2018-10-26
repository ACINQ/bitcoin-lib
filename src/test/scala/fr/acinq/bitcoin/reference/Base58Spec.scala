package fr.acinq.bitcoin.reference

import java.io.InputStreamReader
import java.util

import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization

import org.scalatest.FlatSpec

class Base58Spec extends FlatSpec {

  implicit val format = DefaultFormats

  def resourceStream(resource: String) = classOf[Base58Spec].getResourceAsStream(resource)

  def resourceReader(resource: String) = new InputStreamReader(resourceStream(resource))

  "Base58" should "pass reference client encode/decode tests" in {
    val data = Serialization.read[List[List[String]]](resourceReader("/data/base58_encode_decode.json"))
    data.map(_ match {
      case hex :: expected :: Nil =>
        assert(Base58.encode(fromHexString(hex)) === expected)
        assert(util.Arrays.equals(Base58.decode(expected), fromHexString(hex)))
      case unexpected =>
        println(s"wasn't expecting $unexpected")
    })
  }
}
