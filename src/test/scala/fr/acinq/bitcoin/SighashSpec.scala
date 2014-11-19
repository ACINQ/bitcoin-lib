package fr.acinq.bitcoin

import java.io.InputStreamReader

import org.json4s.DefaultFormats
import org.json4s.jackson.{JsonMethods, Serialization}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class SighashSpec extends FlatSpec {
  implicit val format = DefaultFormats

  def resourceStream(resource: String) = classOf[SighashSpec].getResourceAsStream(resource)

  def resourceReader(resource: String) = new InputStreamReader(resourceStream(resource))

  "bitcoin-lib" should "pass reference client sighash tests" in {
    import shapeless._
    import syntax.std.traversable._
    import HList._
    val stream = classOf[Base58Spec].getResourceAsStream("/sighash.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[Any]]].tail.map(_.toHList[String :: String :: BigInt :: BigInt :: String :: HNil]).map(_ match {
      case Some(raw_transaction :: script :: input_index :: hashType :: signature_hash :: HNil) => {
        val tx = Transaction.read(raw_transaction)
        val hash = Transaction.hashForSigning(tx, input_index.intValue, fromHexString(script), hashType.intValue)
        assert(toHexString(hash.reverse) === signature_hash)
      }
      case None => println("warning: could not parse sighash.json properly!")
    })
  }
}

