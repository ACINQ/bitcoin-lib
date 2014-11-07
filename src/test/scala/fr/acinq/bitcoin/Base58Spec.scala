package fr.acinq.bitcoin

import java.io.InputStreamReader
import java.math.BigInteger
import java.util

import org.json4s.DefaultFormats
import org.json4s.jackson.JsonMethods
import org.json4s.jackson.Serialization
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class Base58Spec extends FlatSpec {
  import fr.acinq.bitcoin.Base58._
  implicit val format = DefaultFormats

  def resourceStream(resource: String) = classOf[Base58Spec].getResourceAsStream(resource)

  def resourceReader(resource: String) = new InputStreamReader(resourceStream(resource))

  "Base58" should "encode byte arrays" in {
    assert(encode("Hello World".getBytes("UTF-8")) === "JxF12TrwUP45BMd")
    assert(encode(BigInteger.valueOf(3471844090L).toByteArray) === "16Ho7Hs")
    assert(encode(new Array[Byte](1)) === "1")
    assert(encode(new Array[Byte](7)) === "1111111")
    assert(encode(new Array[Byte](0)) === "")
  }

  it should "decode strings" in {
    assert(util.Arrays.equals(decode("JxF12TrwUP45BMd"), "Hello World".getBytes("UTF-8")))
    assert(util.Arrays.equals(decode(""), new Array[Byte](0)))
    assert(util.Arrays.equals(decode("1"), new Array[Byte](1)))
    assert(util.Arrays.equals(decode("1111111"), new Array[Byte](7)))
    decode("93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T")
    intercept[NoSuchElementException] {
      decode("This isn't valid base58")
    }
  }

  it should "pass reference client encode/decode tests" in {
    val data = Serialization.read[List[List[String]]](resourceReader("/base58_encode_decode.json"))
    data.map(_ match {
      case hex :: expected :: Nil =>
        assert(Base58.encode(fromHexString(hex)) === expected)
        assert(util.Arrays.equals(Base58.decode(expected), fromHexString(hex)))
      case unexpected =>
        println(s"wasn't expecting $unexpected")
    })
  }

  it should "pass reference client valid keys tests" in {
    import shapeless._
    import syntax.std.traversable._
    import HList._

    val stream = classOf[Base58Spec].getResourceAsStream("/base58_keys_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    json.extract[List[List[Any]]].map(_.toHList[String::String::Map[String, Any]::HNil]).map(_ match {
      case Some(base58 :: hex :: map :: HNil) => {
        val (version, data) = Address.decode(base58)
        val isPrivkey = map.get("isPrivkey").getOrElse(false).asInstanceOf[Boolean]
        val isTestnet = map.get("isTestnet").getOrElse(false).asInstanceOf[Boolean]
        if (isPrivkey) {
          val isCompressed = map.get("isCompressed").getOrElse(false).asInstanceOf[Boolean]
          isCompressed match {
            case true =>
              assert(data.length == 33)
              assert(data(32) == 1)
              assert(toHexString(data.take(32)) == hex)
            case false =>
              assert(data.length == 32)
              assert(toHexString(data) == hex)
          }
        } else {
          val addrType = map("addrType").asInstanceOf[String]
          assert(toHexString(data) == hex)
          (addrType, isTestnet) match {
            case ("pubkey", false) => assert(version == Address.LivenetPubkeyVersion)
            case ("pubkey", true) => assert(version == Address.TestnetPubkeyVersion)
            case ("script", false) => assert(version == Address.LivenetScriptVersion)
            case ("script", true) => assert(version == Address.TestnetScriptVersion)
            case unexpected => println(s"wasn't expecting $unexpected")
          }
        }
        assert(Address.encode(version, data) == base58)
      }
      case None => println("warning: could not parse base58_keys_valid.json properly!")
    })
  }
}
