package fr.acinq.bitcoin.reference

import java.io.InputStreamReader
import java.util

import fr.acinq.bitcoin.Base58.Prefix
import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.{JsonMethods, Serialization}

import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner


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

  it should "pass reference client valid keys tests" in {
    val stream = classOf[Base58Spec].getResourceAsStream("/data/base58_keys_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].map(_ match {
      case JString(base58) :: JString(hex) :: obj :: Nil => {
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val JBool(isTestnet) = obj \ "isTestnet"
        val (version, data) = Base58Check.decode(base58)
        if (isPrivkey) {
          val JBool(isCompressed) = obj \ "isCompressed"
          isCompressed match {
            case true =>
              assert(data.length == 33)
              assert(data.last == 1)
              assert(toHexString(data.take(32)) == hex)
            case false =>
              assert(data.length == 32)
              assert(toHexString(data) == hex)
          }
        } else {
          val JString(addrType) = obj \ "addrType"
          assert(toHexString(data) == hex)
          (addrType, isTestnet) match {
            case ("pubkey", false) => assert(version == Prefix.PubkeyAddress)
            case ("pubkey", true) => assert(version == Prefix.PubkeyAddressTestnet)
            case ("script", false) => assert(version == Prefix.ScriptAddress)
            case ("script", true) => assert(version == Prefix.ScriptAddressTestnet)
            case unexpected => println(s"wasn't expecting $unexpected")
          }
        }
        assert(Base58Check.encode(version, data) == base58)
      }
      case unexpected => println(s"don't know how to parse $unexpected")
    })
  }
}
