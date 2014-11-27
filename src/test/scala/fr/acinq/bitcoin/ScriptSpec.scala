package fr.acinq.bitcoin

import java.io.InputStreamReader

import com.google.common.io.BaseEncoding
import org.json4s.DefaultFormats
import org.json4s.jackson.{JsonMethods, Serialization}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class ScriptSpec extends FlatSpec {
  implicit val format = DefaultFormats

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
  it should "pass reference client sighash tests" in {
    val stream = classOf[ScriptSpec].getResourceAsStream("/script_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[String]]].tail.foreach(_ match {
      case scriptPubKey :: scriptSig :: flags :: comments :: Nil => ()
      case scriptPubKey :: scriptSig :: flags :: Nil => ()
      case _ => ()
    })
  }
}
