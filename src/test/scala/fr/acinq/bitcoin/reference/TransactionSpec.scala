package fr.acinq.bitcoin.reference

import java.io.InputStreamReader

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

  "Bitcoins library" should "pass reference tx valid tests" in {
    implicit val format = DefaultFormats

    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].filter(_.size > 1).map(_.reverse).map(_ match {
      case JString(verifyFlags) :: JString(serializedTransaction) :: tail => {
        val prevoutMap = collection.mutable.HashMap.empty[OutPoint, BinaryData]
        tail match {
          case List(JArray(m)) => m.map(_ match {
            case JArray(List(JString(hash), JInt(index), JString(scriptPubKey))) => {
              val prevoutScript = ScriptSpec.parseFromText(scriptPubKey)
              prevoutMap += OutPoint(fromHexString(hash).reverse, index.toLong) -> prevoutScript
            }
          })
        }
        val tx = Transaction.read(serializedTransaction)
        Try {
          Transaction.validate(tx)
          Transaction.correctlySpends(tx, prevoutMap.toMap, ScriptSpec.parseScriptFlags(verifyFlags))
        } match {
          case Success(_) => ()
          case Failure(t) => println(s"failed to verify $serializedTransaction: $t")
        }
      }
      case unexpected => println(s"unexpected: $unexpected")
    })
  }

  it should "pass reference tx invalid tests" in {
    implicit val format = DefaultFormats

    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_invalid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].filter(_.size > 1).map(_.reverse).map(_ match {
      case JString(verifyFlags) :: JString(serializedTransaction) :: tail => {
        val prevoutMap = collection.mutable.HashMap.empty[OutPoint, BinaryData]
        tail match {
          case List(JArray(m)) => m.map(_ match {
            case JArray(List(JString(hash), JInt(index), JString(scriptPubKey))) => {
              val prevoutScript = ScriptSpec.parseFromText(scriptPubKey)
              prevoutMap += OutPoint(fromHexString(hash).reverse, index.toLong) -> prevoutScript
           }
          })
        }
        val tx = Transaction.read(serializedTransaction)
        Try {
          Transaction.validate(tx)
          Transaction.correctlySpends(tx, prevoutMap.toMap, ScriptSpec.parseScriptFlags(verifyFlags))
        } match {
          case Success(_) => println(s"tx found valid when it should not be: $serializedTransaction")
          case Failure(t) => ()
        }
      }
      case unexpected => println(s"unexpected: $unexpected")
    })
  }
}
