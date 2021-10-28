package fr.acinq.bitcoinscala.reference

import fr.acinq.bitcoinscala.Crypto.PrivateKey
import fr.acinq.bitcoinscala.{Base58, Base58Check, Bech32, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA, Script}
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import java.io.InputStreamReader
import scala.util.Try

class KeyEncodingSpec extends FunSuite {
  implicit val format = DefaultFormats

  test("valid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].map(KeyEncodingSpec.check)
  }

  test("invalid keys") {
    assert(!KeyEncodingSpec.isValidBase58("KxuACDviz8Xvpn1xAh9MfopySZNuyajYMZWz16Dv2mHHryznWUp3"))

    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_invalid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].foreach {
      case JString(value) :: Nil =>
        assert(!KeyEncodingSpec.isValidBase58(value))
        assert(!KeyEncodingSpec.isValidBech32(value))
      case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
    }
  }
}

object KeyEncodingSpec {
  def isValidBase58(input: String): Boolean = Try {
    val (prefix, bin) = Base58Check.decode(input)
    prefix match {
      case Base58.Prefix.SecretKey | Base58.Prefix.SecretKeyTestnet => Try(PrivateKey.fromBin(bin)).isSuccess
      case Base58.Prefix.PubkeyAddress | Base58.Prefix.PubkeyAddressTestnet => bin.length == 20
      case _ => false
    }
  } getOrElse false

  def isValidBech32(input: String): Boolean = Try {
    Bech32.decodeWitnessAddress(input) match {
      case (hrp, 0, bin) if (hrp == "bc" || hrp == "tb" || hrp == "bcrt") && (bin.length == 20 || bin.length == 32) => true
      case _ => false
    }
  } getOrElse false

  def check(data: List[JValue]): Unit = {
    data match {
      case JString(encoded) :: JString(hex) :: obj :: Nil => {
        val bin = ByteVector.fromValidHex(hex)
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val isCompressed = obj \ "isCompressed" match {
          case JBool(value) => value
          case _ => None
        }
        val JString(chain) = obj \ "chain"
        if (isPrivkey) {
          val (version, data) = Base58Check.decode(encoded)
          assert(version == Base58.Prefix.SecretKey || version == Base58.Prefix.SecretKeyTestnet)
          assert(data.take(32) == bin)
        } else encoded.head match {
          case '1' | 'm' | 'n' =>
            val (version, data) = Base58Check.decode(encoded)
            assert(version == Base58.Prefix.PubkeyAddress || version == Base58.Prefix.PubkeyAddressTestnet)
            val OP_DUP :: OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil = Script.parse(bin)
            assert(data == hash)
          case '2' | '3' =>
            val (version, data) = Base58Check.decode(encoded)
            assert(version == Base58.Prefix.ScriptAddress || version == Base58.Prefix.ScriptAddressTestnet)
            val OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUAL :: Nil = Script.parse(bin)
            assert(data == hash)
          case _ => encoded.substring(0, 2) match {
            case "bc" | "tb" =>
              val (_, tag, program) = Bech32.decodeWitnessAddress(encoded)
              val op :: OP_PUSHDATA(hash, _) :: Nil = Script.parse(bin)
              assert(Script.simpleValue(op) == tag)
              assert(program == hash)
          }
        }
      }
      case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
    }
  }
}
