package fr.acinq.bitcoin.reference

import java.io.InputStreamReader

import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JInt, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FlatSpec
import scodec.bits.ByteVector

class SighashSpec extends FlatSpec {
  implicit val format = DefaultFormats

  "bitcoin-lib" should "pass reference client sighash tests" in {
    val stream = classOf[Base58Spec].getResourceAsStream("/data/sighash.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[JValue]]].tail.map(_ match {
      case JString(raw_transaction) :: JString(script) :: JInt(input_index) :: JInt(hashType) :: JString(signature_hash) :: Nil => {
        val tx = Transaction.read(raw_transaction)
        val hash = Transaction.hashForSigning(tx, input_index.intValue, ByteVector.fromValidHex(script), hashType.intValue)
        assert(hash.reverse === ByteVector32(ByteVector.fromValidHex(signature_hash)))
      }
      case _ => println("warning: could not parse sighash.json properly!")
    })
  }
}
