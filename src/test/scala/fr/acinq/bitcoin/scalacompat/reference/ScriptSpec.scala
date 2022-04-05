package fr.acinq.bitcoin.scalacompat.reference

import fr.acinq.bitcoin.scalacompat._
import org.json4s.JsonAST.{JArray, JDouble, JString}
import org.json4s.jackson.JsonMethods
import org.json4s.{DefaultFormats, JValue}
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import java.io.InputStreamReader
import scala.annotation.tailrec
import scala.util.Try

/**
 * bitcoin core reference script tests
 * see bitcoin/src/test/script_tests.cpp for implementation details
 */

object ScriptSpec {

  val name2code: Map[String, Int] = Map(
    "0" -> 0x00,
    "PUSHDATA1" -> 0x4c,
    "PUSHDATA2" -> 0x4d,
    "PUSHDATA4" -> 0x4e,
    "1NEGATE" -> 0x4f,
    "RESERVED" -> 0x50,
    "1" -> 0x51,
    "2" -> 0x52,
    "3" -> 0x53,
    "4" -> 0x54,
    "5" -> 0x55,
    "6" -> 0x56,
    "7" -> 0x57,
    "8" -> 0x58,
    "9" -> 0x59,
    "10" -> 0x5a,
    "11" -> 0x5b,
    "12" -> 0x5c,
    "13" -> 0x5d,
    "14" -> 0x5e,
    "15" -> 0x5f,
    "16" -> 0x60,
    "NOP" -> 0x61,
    "VER" -> 0x62,
    "IF" -> 0x63,
    "NOTIF" -> 0x64,
    "VERIF" -> 0x65,
    "VERNOTIF" -> 0x66,
    "ELSE" -> 0x67,
    "ENDIF" -> 0x68,
    "VERIFY" -> 0x69,
    "RETURN" -> 0x6a,
    "TOALTSTACK" -> 0x6b,
    "FROMALTSTACK" -> 0x6c,
    "2DROP" -> 0x6d,
    "2DUP" -> 0x6e,
    "3DUP" -> 0x6f,
    "2OVER" -> 0x70,
    "2ROT" -> 0x71,
    "2SWAP" -> 0x72,
    "IFDUP" -> 0x73,
    "DEPTH" -> 0x74,
    "DROP" -> 0x75,
    "DUP" -> 0x76,
    "NIP" -> 0x77,
    "OVER" -> 0x78,
    "PICK" -> 0x79,
    "ROLL" -> 0x7a,
    "ROT" -> 0x7b,
    "SWAP" -> 0x7c,
    "TUCK" -> 0x7d,
    "CAT" -> 0x7e,
    "SUBSTR" -> 0x7f,
    "LEFT" -> 0x80,
    "RIGHT" -> 0x81,
    "SIZE" -> 0x82,
    "INVERT" -> 0x83,
    "AND" -> 0x84,
    "OR" -> 0x85,
    "XOR" -> 0x86,
    "EQUAL" -> 0x87,
    "EQUALVERIFY" -> 0x88,
    "RESERVED1" -> 0x89,
    "RESERVED2" -> 0x8a,
    "1ADD" -> 0x8b,
    "1SUB" -> 0x8c,
    "2MUL" -> 0x8d,
    "2DIV" -> 0x8e,
    "NEGATE" -> 0x8f,
    "ABS" -> 0x90,
    "NOT" -> 0x91,
    "0NOTEQUAL" -> 0x92,
    "ADD" -> 0x93,
    "SUB" -> 0x94,
    "MUL" -> 0x95,
    "DIV" -> 0x96,
    "MOD" -> 0x97,
    "LSHIFT" -> 0x98,
    "RSHIFT" -> 0x99,
    "BOOLAND" -> 0x9a,
    "BOOLOR" -> 0x9b,
    "NUMEQUAL" -> 0x9c,
    "NUMEQUALVERIFY" -> 0x9d,
    "NUMNOTEQUAL" -> 0x9e,
    "LESSTHAN" -> 0x9f,
    "GREATERTHAN" -> 0xa0,
    "LESSTHANOREQUAL" -> 0xa1,
    "GREATERTHANOREQUAL" -> 0xa2,
    "MIN" -> 0xa3,
    "MAX" -> 0xa4,
    "WITHIN" -> 0xa5,
    "RIPEMD160" -> 0xa6,
    "SHA1" -> 0xa7,
    "SHA256" -> 0xa8,
    "HASH160" -> 0xa9,
    "HASH256" -> 0xaa,
    "CODESEPARATOR" -> 0xab,
    "CHECKSIG" -> 0xac,
    "CHECKSIGVERIFY" -> 0xad,
    "CHECKMULTISIG" -> 0xae,
    "CHECKMULTISIGVERIFY" -> 0xaf,
    "NOP1" -> 0xb0,
    "NOP2" -> 0xb1,
    "CHECKLOCKTIMEVERIFY" -> 0xb1,
    "NOP3" -> 0xb2,
    "CHECKSEQUENCEVERIFY" -> 0xb2,
    "NOP4" -> 0xb3,
    "NOP5" -> 0xb4,
    "NOP6" -> 0xb5,
    "NOP7" -> 0xb6,
    "NOP8" -> 0xb7,
    "NOP9" -> 0xb8,
    "NOP10" -> 0xb9,
    "SMALLINTEGER" -> 0xfa,
    "INVALIDOPCODE" -> 0xff
  )

  def parseFromText(input: String): ByteVector = {
    @tailrec
    def parseInternal(tokens: List[String], acc: ByteVector = ByteVector.empty): ByteVector = tokens match {
      case Nil => acc
      case head :: tail if head.matches("^-?[0-9]*$") => head.toLong match {
        case -1 => parseInternal(tail, acc :+ ScriptElt.elt2code(OP_1NEGATE).toByte)
        case 0 => parseInternal(tail, acc :+ ScriptElt.elt2code(OP_0).toByte)
        case value if value >= 1 && value <= 16 =>
          val bytes = ByteVector((ScriptElt.elt2code(OP_1) - 1 + value).toByte)
          parseInternal(tail, acc ++ bytes)
        case value =>
          val bytes = Script.encodeNumber(value)
          parseInternal(tail, acc ++ Script.write(OP_PUSHDATA(bytes) :: Nil))
      }
      case head :: tail if name2code.contains(head) => parseInternal(tail, acc :+ name2code(head).toByte)
      case head :: tail if head.startsWith("0x") => parseInternal(tail, acc ++ ByteVector.fromValidHex(head))
      case head :: tail if head.startsWith("'") && head.endsWith("'") => parseInternal(tail, acc ++ Script.write(OP_PUSHDATA(ByteVector.view(head.stripPrefix("'").stripSuffix("'").getBytes("UTF-8"))) :: Nil))
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

  import fr.acinq.bitcoin.ScriptFlags._

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
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" -> SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    "CLEANSTACK" -> SCRIPT_VERIFY_CLEANSTACK,
    "MINIMALIF" -> SCRIPT_VERIFY_MINIMALIF,
    "NULLFAIL" -> SCRIPT_VERIFY_NULLFAIL,
    "CHECKLOCKTIMEVERIFY" -> SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    "CHECKSEQUENCEVERIFY" -> SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    "WITNESS" -> SCRIPT_VERIFY_WITNESS,
    "WITNESS_PUBKEYTYPE" -> SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    "CONST_SCRIPTCODE" -> SCRIPT_VERIFY_CONST_SCRIPTCODE
  )

  def parseScriptFlags(strFlags: String): Int = if (strFlags.isEmpty) 0 else strFlags.split(",").map(mapFlagNames(_)).foldLeft(0)(_ | _)

  def creditTx(scriptPubKey: ByteVector, amount: Btc) = Transaction(version = 1,
    txIn = TxIn(OutPoint(ByteVector32.Zeroes, -1), Script.write(OP_0 :: OP_0 :: Nil), 0xffffffff) :: Nil,
    txOut = TxOut(amount, scriptPubKey) :: Nil,
    lockTime = 0)

  def spendingTx(scriptSig: ByteVector, tx: Transaction) = Transaction(version = 1,
    txIn = TxIn(OutPoint(Crypto.hash256(Transaction.write(tx)), 0), scriptSig, 0xffffffff) :: Nil,
    txOut = TxOut(tx.txOut(0).amount, ByteVector.empty) :: Nil,
    lockTime = 0)

  // use 0 btc if no amount is specified
  def runTest(witnessText: Seq[String], scriptSigText: String, scriptPubKeyText: String, flags: String, comments: Option[String], expectedText: String): Unit =
    runTest(witnessText, 0 btc, scriptSigText, scriptPubKeyText, flags, comments, expectedText)

  def runTest(witnessText: Seq[String], amount: Btc, scriptSigText: String, scriptPubKeyText: String, flags: String, comments: Option[String], expectedText: String): Unit = {
    val witness = ScriptWitness(witnessText.map(ByteVector.fromValidHex(_)))
    val scriptPubKey = parseFromText(scriptPubKeyText)
    val scriptSig = parseFromText(scriptSigText)
    val tx = spendingTx(scriptSig, creditTx(scriptPubKey, amount)).updateWitness(0, witness)
    val ctx = Script.Context(tx, 0, amount)
    val runner = new Script.Runner(ctx, parseScriptFlags(flags))

    val result = Try(runner.verifyScripts(scriptSig, scriptPubKey, witness)).getOrElse(false)
    val expected = expectedText == "OK"
    if (result != expected) {
      throw new RuntimeException(comments.getOrElse(""))
    }
  }

  def runTest(json: JValue): Int = {
    implicit val format = DefaultFormats

    var count = 0
    // use tail to skip the first line of the .json file
    json.extract[List[List[JValue]]].tail.foreach {
      case JString(_) :: Nil => ()
      case JString(scriptSig) :: JString(scriptPubKey) :: JString(flags) :: JString(expected) :: JString(comments) :: Nil =>
        ScriptSpec.runTest(Seq.empty[String], scriptSig, scriptPubKey, flags, Some(comments), expected)
        count = count + 1
      case JString(scriptSig) :: JString(scriptPubKey) :: JString(flags) :: JString(expected) :: Nil =>
        ScriptSpec.runTest(Seq.empty[String], scriptSig, scriptPubKey, flags, None, expected)
        count = count + 1
      case JArray(m) :: JString(scriptSig) :: JString(scriptPubKey) :: JString(flags) :: JString(expected) :: JString(comments) :: Nil =>
        val witnessText: Seq[String] = m.take(m.length - 1).map {
          case JString(value) => value
          case unexpected => throw new RuntimeException(s"expected a witness item (string), got $unexpected")
        }
        val amount: Btc = m.last match {
          case JDouble(value) => Btc(value)
          case unexpected => throw new RuntimeException(s"expected an amount, got $unexpected")
        }
        ScriptSpec.runTest(witnessText, amount, scriptSig, scriptPubKey, flags, Some(comments), expected)
        count = count + 1
      case JArray(m) :: JString(scriptSig) :: JString(scriptPubKey) :: JString(flags) :: JString(expected) :: Nil =>
        val witnessText: Seq[String] = m.take(m.length - 1).map {
          case JString(value) => value
          case unexpected => throw new RuntimeException(s"expected a witness item (string), got $unexpected")
        }
        val amount: Btc = m.last match {
          case JDouble(value) => Btc(value)
          case unexpected => throw new RuntimeException(s"expected an amount, got $unexpected")
        }
        ScriptSpec.runTest(witnessText, amount, scriptSig, scriptPubKey, flags, None, expected)
        count = count + 1
      case unexpected => throw new RuntimeException(s"cannot parse $unexpected")
    }
    count
  }
}

class ScriptSpec extends FunSuite {
  test("reference client script tests") {
    val stream = classOf[ScriptSpec].getResourceAsStream("/data/script_tests.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    val count = ScriptSpec.runTest(json)
    println(s"$count reference script tests passed")
  }
}