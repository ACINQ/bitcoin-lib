package fr.acinq.bitcoin.reference

import java.io.{InputStream, InputStreamReader}

import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JArray, JInt, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{FlatSpec, Matchers}

import scala.util.{Failure, Success, Try}

@RunWith(classOf[JUnitRunner])
class TransactionSpec extends FlatSpec with Matchers {

  def process(stream: InputStream, valid: Boolean) : Unit = {
    implicit val format = DefaultFormats
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].filter(_.size > 1).map(_ match {
      case JArray(m) :: JString(serializedTransaction) :: JString(verifyFlags) :: Nil => {
        val prevoutMap = collection.mutable.HashMap.empty[OutPoint, BinaryData]
        m.map(_ match {
          case JArray(List(JString(hash), JInt(index), JString(scriptPubKey))) => {
            val prevoutScript = ScriptSpec.parseFromText(scriptPubKey)
            prevoutMap += OutPoint(fromHexString(hash).reverse, index.toLong) -> prevoutScript
          }
        })

        val tx = Transaction.read(serializedTransaction)
        Try {
          Transaction.validate(tx)
          Transaction.correctlySpends(tx, prevoutMap.toMap, ScriptSpec.parseScriptFlags(verifyFlags))
        } match {
          case Success(_) if valid => ()
          case Success(_) if !valid => throw new RuntimeException(s"$serializedTransaction should not be valid")
          case Failure(t) if !valid => ()
          case Failure(t) if valid => throw new RuntimeException(s"$serializedTransaction should be valid", t)
        }
      }
      case unexpected => throw new RuntimeException(s"unexpected: $unexpected")
    })
  }

  "Bitcoins library" should "pass reference tx valid tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_valid.json")
    process(stream, true)
 }

  it should "pass reference tx invalid tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_invalid.json")
    process(stream, false)
  }
}
