package fr.acinq.bitcoin.reference

import java.io.InputStreamReader
import java.util

import fr.acinq.bitcoin.Base58.Prefix
import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.{JsonMethods, Serialization}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
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
      case JString(encoded) :: JString(hex) :: obj :: Nil => {
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val isCompressed = obj \ "isCompressed" match {
          case JBool(value) => value
          case _ => None
        }
        val JString(chain) = obj \ "chain"
        if (isPrivkey) {
          val (version, data) = Base58Check.decode(encoded)
          assert(version == Base58.Prefix.SecretKey || version == Base58.Prefix.SecretKeyTestnet)
          assert(BinaryData(data.take(32)) == BinaryData(hex))
        } else encoded.head match {
          case '1' | 'm' | 'n' =>
            val (version, data) = Base58Check.decode(encoded)
            assert(version == Base58.Prefix.PubkeyAddress || version == Base58.Prefix.PubkeyAddressTestnet)
            val OP_DUP :: OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil = Script.parse(hex)
            assert(data == hash)
          case '2' | '3' =>
            val (version, data) = Base58Check.decode(encoded)
            assert(version == Base58.Prefix.ScriptAddress || version == Base58.Prefix.ScriptAddressTestnet)
            val OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUAL :: Nil = Script.parse(hex)
            assert(data == hash)
          case _ => encoded.substring(0, 2) match {
            case "bc" | "tb" =>
              val (_, tag, program) = Bech32.decodeWitnessAddress(encoded)
              val op :: OP_PUSHDATA(hash, _) :: Nil = Script.parse(hex)
              assert(Script.simpleValue(op) == tag)
              assert(program == hash)
          }
        }
      }
      case unexpected => println(s"don't know how to parse $unexpected")
    })
  }
}
