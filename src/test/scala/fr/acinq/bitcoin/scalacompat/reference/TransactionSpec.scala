package fr.acinq.bitcoin.scalacompat.reference

import fr.acinq.bitcoin.scalacompat
import fr.acinq.bitcoin.scalacompat.reference.ScriptSpec.{parseFromText, parseScriptFlags}
import fr.acinq.bitcoin.scalacompat._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JArray, JInt, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.{FlatSpec, Matchers}
import scodec.bits.ByteVector

import java.io.{InputStream, InputStreamReader}
import scala.util.{Failure, Success, Try}

object TransactionSpec {
  def process(json: JValue, valid: Boolean): Unit = {
    implicit val format: DefaultFormats.type = DefaultFormats
    var comment = ""
    json.extract[List[List[JValue]]].foreach {
      case JString(value) :: Nil => comment = value
      case JArray(m) :: JString(serializedTransaction) :: JString(verifyFlags) :: Nil =>
        val prevoutMap = collection.mutable.HashMap.empty[OutPoint, ByteVector]
        val prevamountMap = collection.mutable.HashMap.empty[OutPoint, Satoshi]
        m.map {
          case JArray(List(JString(hash), JInt(index), JString(scriptPubKey))) =>
            val prevoutScript = parseFromText(scriptPubKey)
            prevoutMap += OutPoint(TxId(ByteVector32.fromValidHex(hash)), index.toLong) -> prevoutScript
          case JArray(List(JString(hash), JInt(index), JString(scriptPubKey), JInt(amount))) =>
            val prevoutScript = parseFromText(scriptPubKey)
            prevoutMap += OutPoint(TxId(ByteVector32.fromValidHex(hash)), index.toLong) -> prevoutScript
            prevamountMap += OutPoint(TxId(ByteVector32.fromValidHex(hash)), index.toLong) -> Satoshi(amount.toLong)
          case _ => ()
        }

        val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
        Try {
          Transaction.validate(tx)
          for (i <- tx.txIn.indices if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
            val prevOutputScript = prevoutMap(tx.txIn(i).outPoint)
            val amount = prevamountMap.getOrElse(tx.txIn(i).outPoint, 0 sat)
            val ctx = Script.Context(tx, i, amount)
            val runner = new Script.Runner(ctx, parseScriptFlags(verifyFlags))
            if (!runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript, tx.txIn(i).witness)) throw new RuntimeException(s"tx ${tx.txid} does not spend its input # $i")
          }
        } match {
          case Success(_) => if (!valid) throw new RuntimeException(s"$serializedTransaction should not be valid, [$comment]")
          case Failure(t) => if (valid) throw new RuntimeException(s"$serializedTransaction should be valid, [$comment]", t)
        }
      case unexpected => throw new RuntimeException(s"unexpected: $unexpected")
    }
  }

  def process(stream: InputStream, valid: Boolean): Unit = {
    val json = JsonMethods.parse(new InputStreamReader(stream))
    process(json, valid)
  }
}

class TransactionSpec extends FlatSpec with Matchers {

  import TransactionSpec._

  "Bitcoins library" should "pass reference tx valid tests" in {
    val stream = classOf[scalacompat.reference.TransactionSpec].getResourceAsStream("/data/tx_valid.json")
    process(stream, valid = true)
  }

  it should "pass reference tx invalid tests" in {
    val stream = classOf[scalacompat.reference.TransactionSpec].getResourceAsStream("/data/tx_invalid.json")
    process(stream, valid = false)
  }
}
