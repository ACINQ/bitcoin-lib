package fr.acinq.bitcoin.reference

import java.io.InputStreamReader

import fr.acinq.bitcoin._
import org.json4s.DefaultFormats
import org.json4s.jackson.JsonMethods
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

import scala.util.Try

object ScriptSpec {
  def parseFromText(input: String): Array[Byte] = {
    def parseInternal(tokens: List[String], acc: Array[Byte] = Array.empty[Byte]): Array[Byte] = tokens match {
      case Nil => acc
      case head :: tail if head.matches("^-?[0-9]*$") => head.toLong match {
        case -1 => parseInternal(tail, acc :+ ScriptElt.elt2code(OP_1NEGATE).toByte)
        case 0 => parseInternal(tail, acc :+ ScriptElt.elt2code(OP_0).toByte)
        case value if value >= 1 && value <= 16 =>
          val bytes = Array((ScriptElt.elt2code(OP_1) - 1 + value).toByte)
          parseInternal(tail, acc ++ bytes)
        case value =>
          val bytes = Script.encodeNumber(value)
          parseInternal(tail, acc ++ Script.write(OP_PUSHDATA(bytes) :: Nil))
      }
      case head :: tail if ScriptElt.name2code.get(head).isDefined => parseInternal(tail, acc :+ ScriptElt.name2code(head).toByte)
      case head :: tail if head.startsWith("0x") => parseInternal(tail, acc ++ fromHexString(head))
      case head :: tail if head.startsWith("'") && head.endsWith("'") => parseInternal(tail, acc ++ Script.write(OP_PUSHDATA(head.stripPrefix("'").stripSuffix("'").getBytes("UTF-8")) :: Nil))
    }
    try {
      val tokens = input.split(' ').filterNot(_.isEmpty).map(_.stripPrefix("OP_")).toList
      val bytes = parseInternal(tokens)
      bytes
    }
    catch {
      case t: Throwable => throw new RuntimeException(s"cannot parse $input", t)
    }
  }

  import ScriptFlags._

  val mapFlagNames = Map(
    "NONE" -> SCRIPT_VERIFY_NONE,
    "P2SH" -> SCRIPT_VERIFY_P2SH,
    "STRICTENC" -> SCRIPT_VERIFY_STRICTENC,
    "DERSIG" -> SCRIPT_VERIFY_DERSIG,
    "LOW_S" -> SCRIPT_VERIFY_LOW_S,
    "SIGPUSHONLY" -> SCRIPT_VERIFY_SIGPUSHONLY,
    "MINIMALDATA" -> SCRIPT_VERIFY_MINIMALDATA,
    "NULLDUMMY" -> SCRIPT_VERIFY_NULLDUMMY,
    "DISCOURAGE_UPGRADABLE_NOPS" -> SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    "CLEANSTACK" -> SCRIPT_VERIFY_CLEANSTACK,
    "CHECKLOCKTIMEVERIFY" -> SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
  )

  def parseScriptFlags(strFlags: String): Int = if (strFlags.isEmpty) 0 else strFlags.split(",").map(mapFlagNames(_)).foldLeft(0)(_ | _)

  def creditTx(scriptPubKey: Array[Byte]) = Transaction(version = 1,
    txIn = TxIn(OutPoint(new Array[Byte](32), -1), Script.write(OP_0 :: OP_0 :: Nil), 0xffffffff) :: Nil,
    txOut = TxOut(0, scriptPubKey) :: Nil,
    lockTime = 0)

  def spendingTx(scriptSig: Array[Byte], tx: Transaction) = Transaction(version = 1,
    txIn = TxIn(OutPoint(Crypto.hash256(Transaction.write(tx)), 0), scriptSig, 0xffffffff) :: Nil,
    txOut = TxOut(0, Array.empty[Byte]) :: Nil,
    lockTime = 0)

  def runTest(scriptSigText: String, scriptPubKeyText: String, flags: String, comments: Option[String], expectedResult: Boolean): Unit = {
    val scriptPubKey = parseFromText(scriptPubKeyText)
    val scriptSig = parseFromText(scriptSigText)
    val tx = spendingTx(scriptSig, creditTx(scriptPubKey))
    val ctx = Script.Context(tx, 0)
    val runner = new Script.Runner(ctx, parseScriptFlags(flags))

    val result = Try(runner.verifyScripts(scriptSig, scriptPubKey)).getOrElse(false)
    if (result != expectedResult) {
      throw new RuntimeException(comments.getOrElse(""))
    }
  }
}

@RunWith(classOf[JUnitRunner])
class ScriptSpec extends FlatSpec {

  implicit val format = DefaultFormats

  "Script" should "pass reference client valid script tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/script_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[String]]].tail.foreach(_ match {
      case scriptSig :: scriptPubKey :: flags :: comments :: Nil => ScriptSpec.runTest(scriptSig, scriptPubKey, flags, Some(comments), true)
      case scriptSig :: scriptPubKey :: flags :: Nil => ScriptSpec.runTest(scriptSig, scriptPubKey, flags, None, true)
      case _ => ()
    })
  }
  it should "pass reference client invalid script tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/script_invalid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[String]]].tail.foreach(_ match {
      case scriptSig :: scriptPubKey :: flags :: comments :: Nil => ScriptSpec.runTest(scriptSig, scriptPubKey, flags, Some(comments), false)
      case scriptSig :: scriptPubKey :: flags :: Nil => ScriptSpec.runTest(scriptSig, scriptPubKey, flags, None, false)
      case _ => ()
    })
  }
}
