package fr.acinq.bitcoin.reference

import java.io.{InputStream, InputStreamReader}

import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JArray, JInt, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.{FlatSpec, Matchers}
import scodec.bits.ByteVector

import scala.util.{Failure, Success, Try}

object TransactionSpec {
  def process(json: JValue, valid: Boolean): Unit = {
    implicit val format = DefaultFormats
    var comment = ""
    json.extract[List[List[JValue]]].map(_ match {
      case JString(value) :: Nil => comment = value
      case JArray(m) :: JString(serializedTransaction) :: JString(verifyFlags) :: Nil => {
        val prevoutMap = collection.mutable.HashMap.empty[OutPoint, ByteVector]
        val prevamountMap = collection.mutable.HashMap.empty[OutPoint, Satoshi]
        m.map(_ match {
          case JArray(List(JString(hash), JInt(index), JString(scriptPubKey))) => {
            val prevoutScript = ScriptSpec.parseFromText(scriptPubKey)
            prevoutMap += OutPoint(ByteVector32(ByteVector.fromValidHex(hash).reverse), index.toLong) -> prevoutScript
          }
          case JArray(List(JString(hash), JInt(index), JString(scriptPubKey), JInt(amount))) => {
            val prevoutScript = ScriptSpec.parseFromText(scriptPubKey)
            prevoutMap += OutPoint(ByteVector32(ByteVector.fromValidHex(hash).reverse), index.toLong) -> prevoutScript
            prevamountMap += OutPoint(ByteVector32(ByteVector.fromValidHex(hash).reverse), index.toLong) -> Satoshi(amount.toLong)
          }
        })

        val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
        Try {
          Transaction.validate(tx)
          for (i <- 0 until tx.txIn.length if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
            val prevOutputScript = prevoutMap(tx.txIn(i).outPoint)
            val amount = prevamountMap.get(tx.txIn(i).outPoint).getOrElse(0 sat)
            val ctx = new Script.Context(tx, i, amount)
            val runner = new Script.Runner(ctx, ScriptSpec.parseScriptFlags(verifyFlags))
            if (!runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript, tx.txIn(i).witness)) throw new RuntimeException(s"tx ${tx.txid} does not spend its input # $i")
          }
        } match {
          case Success(_) if valid => ()
          case Success(_) if !valid => throw new RuntimeException(s"$serializedTransaction should not be valid, [$comment]")
          case Failure(_) if !valid => ()
          case Failure(t) if valid => throw new RuntimeException(s"$serializedTransaction should be valid, [$comment]", t)
        }
      }
      case unexpected => throw new RuntimeException(s"unexpected: $unexpected")
    })
  }

  def process(stream: InputStream, valid: Boolean): Unit = {
    implicit val format = DefaultFormats
    val json = JsonMethods.parse(new InputStreamReader(stream))
    process(json, valid)
  }
}

class TransactionSpec extends FlatSpec with Matchers {

  import TransactionSpec._

  "Bitcoins library" should "pass reference tx valid tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_valid.json")
    process(stream, true)
  }

  it should "pass reference tx invalid tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/tx_invalid.json")
    process(stream, false)
  }
}
