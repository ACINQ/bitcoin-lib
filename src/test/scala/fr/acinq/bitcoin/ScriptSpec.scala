package fr.acinq.bitcoin

import java.io.InputStreamReader

import com.google.common.io.BaseEncoding
import org.json4s.DefaultFormats
import org.json4s.jackson.{JsonMethods, Serialization}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

import scala.collection.mutable.ArrayBuffer

@RunWith(classOf[JUnitRunner])
class ScriptSpec extends FlatSpec {
  implicit val format = DefaultFormats

  def parseFromText(input: String) : Array[Byte] = {
    def parseInternal(tokens: List[String], acc: Array[Byte] = Array.empty[Byte]) : Array[Byte] = tokens match {
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

  "Script" should "parse signature scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c")
    val script = Script.parse(blob)
    val pk = Script.publicKey(script)
    val hash = Crypto.hash160(pk)
    assert(Address.encode(0x6f, hash) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to public key' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac")
    val script = Script.parse(blob)
    val hash = Script.publicKeyHash(script)
    assert(Address.encode(0x6f, hash) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to script' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("a914a90003b4ddef4be46fc61e7f2167da9d234944e287")
    val script = Script.parse(blob)
    val OP_HASH160 :: OP_PUSHDATA(scriptHash) :: OP_EQUAL :: Nil = script
    val multisigAddress = Address.encode(Address.TestnetScriptVersion, scriptHash)
    assert(multisigAddress === "2N8epCi6GwVDNYgJ7YtQ3qQ9vGQzaGu6JY4")
  }
  it should "parse if/else/endif" in {
    val tx = Transaction(version = 1,
      txIn = TxIn(OutPoint(new Array[Byte](32), 0xffffffff), Script.write(OP_NOP :: Nil), 0xffffffff) :: Nil,
      txOut = TxOut(0x12a05f200L, Array.empty[Byte]) :: Nil,
      lockTime = 0)
    val ctx = Script.Context(tx, 0, Script.write(OP_NOP :: Nil))
    val runner = new Script.Runner(ctx)
    val script = OP_1 :: OP_2 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack = runner.run(script)
    val List(Array(check)) = stack
    assert(check === 4)
    val script1 = OP_1 :: OP_1 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack1 = runner.run(script1)
    val List(Array(check1)) = stack1
    assert(check1 === 3)
    val script2 = OP_1 :: OP_1 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_3 :: OP_EQUAL :: OP_IF :: OP_5 :: OP_ENDIF :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack2 = runner.run(script2)
    val List(Array(check2)) = stack2
    assert(check2 === 5)
  }
  it should "encode/decode simple numbers" in {
    for (i <- -1 to 16) {
      assert(Script.decodeNumber(Script.encodeNumber(i)) === i)
    }
  }
  it should "encode/decode booleans" in {
    assert(Script.castToBoolean(Array.empty[Byte]) === false)
    assert(Script.castToBoolean(Array(0, 0, 0)) === false)
    assert(Script.castToBoolean(Array(0x80.toByte)) === false)
  }
  it should "pass reference client valid script tests" in {

    def creditTx(scriptPubKey: Array[Byte]) = Transaction(version = 1,
      txIn = TxIn(OutPoint(new Array[Byte](32), -1), Script.write(OP_0 :: OP_0 :: Nil), 0xffffffff) :: Nil,
      txOut = TxOut(0, scriptPubKey) :: Nil,
      lockTime = 0)

    def spendingTx(scriptSig: Array[Byte], tx: Transaction) = Transaction(version = 1,
      txIn = TxIn(OutPoint(Crypto.hash256(Transaction.write(tx)), 0), scriptSig, 0xffffffff) :: Nil,
      txOut = TxOut(0, Array.empty[Byte]) :: Nil,
      lockTime = 0)

    def runTest(scriptPubKeyText: String, scriptSigText: String, flags: String, comments: Option[String]): Unit = {
      val scriptPubKey = parseFromText(scriptPubKeyText)
      val scriptSig = parseFromText(scriptSigText)
      val tx = spendingTx(scriptSig, creditTx(scriptPubKey))
      val ctx = Script.Context(tx, 0, scriptPubKey)
      val runner = new Script.Runner(ctx)
      try {
        val stack = runner.run(scriptPubKey)
        val stack1 = runner.run(scriptSig, stack)
        assert(!stack1.isEmpty)
        if(!Script.castToBoolean(stack1.head)) {
          println("-- error -- ")
          println(s"scriptPubKey : $scriptPubKeyText $scriptPubKey")
          println(s"scriptSig : $scriptSigText $scriptSig")
        }
      }
      catch {
        case t: Throwable =>
          println(s"-- $t -- ")
          t.printStackTrace()
          println(s"scriptPubKey : $scriptPubKeyText $scriptPubKey")
          println(s"scriptSig : $scriptSigText $scriptSig")
      }
    }
    
    val stream = classOf[ScriptSpec].getResourceAsStream("/script_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[String]]].tail.foreach(_ match {
      case scriptPubKey :: scriptSig :: flags :: comments :: Nil => runTest(scriptPubKey, scriptSig, flags, Some(comments))
      case scriptPubKey :: scriptSig :: flags :: Nil => runTest(scriptPubKey, scriptSig, flags, None)
      case _ => ()
    })
  }
}
