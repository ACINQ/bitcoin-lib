package fr.acinq.bitcoin

import com.google.common.io.BaseEncoding
import fr.acinq.bitcoin.Base58.Prefix
import fr.acinq.bitcoin.Crypto.PublicKey
import org.scalatest.FlatSpec
import scodec.bits._

class ScriptSpec extends FlatSpec {
  "Script" should "parse signature scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c")
    val script = Script.parse(blob)
    val pk = Script.publicKey(script)
    val hash = Crypto.hash160(pk)
    assert(Base58Check.encode(Prefix.PubkeyAddressTestnet, hash) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to public key' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac")
    val script = Script.parse(blob)
    val hash = Script.publicKeyHash(script)
    assert(Base58Check.encode(Prefix.PubkeyAddressTestnet, hash) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to script' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("a914a90003b4ddef4be46fc61e7f2167da9d234944e287")
    val script = Script.parse(blob)
    val OP_HASH160 :: OP_PUSHDATA(scriptHash, _) :: OP_EQUAL :: Nil = script
    val multisigAddress = Base58Check.encode(Prefix.ScriptAddressTestnet, scriptHash)
    assert(multisigAddress === "2N8epCi6GwVDNYgJ7YtQ3qQ9vGQzaGu6JY4")
  }
  it should "detect 'pay to script' scripts" in {
    val script = hex"a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787"
    assert(Script.isPayToScript(script))
  }
  it should "detect 'native witness' scripts" in {
    val p2wpkh = Script.pay2wpkh(PublicKey(hex"029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c8871"))
    assert(Script.isNativeWitnessScript(p2wpkh))
    assert(Script.isNativeWitnessScript(Script.write(p2wpkh)))
    val p2wsh = Script.pay2wsh(hex"a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787")
    assert(Script.isNativeWitnessScript(p2wsh))
    assert(Script.isNativeWitnessScript(Script.write(p2wsh)))
  }
  it should "parse if/else/endif" in {
    val tx = Transaction(version = 1,
      txIn = TxIn(OutPoint(ByteVector32.Zeroes, 0xffffffff), Script.write(OP_NOP :: Nil), 0xffffffff) :: Nil,
      txOut = TxOut(0x12a05f200L sat, ByteVector.empty) :: Nil,
      lockTime = 0)
    val ctx = Script.Context(tx, 0, 0 sat)
    val runner = new Script.Runner(ctx)
    val script = OP_1 :: OP_2 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack = runner.run(script)
    assert(stack === List(ByteVector(4)))
    val script1 = OP_1 :: OP_1 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack1 = runner.run(script1)
    assert(stack1 === List(ByteVector(3)))
    val script2 = OP_1 :: OP_1 :: OP_EQUAL :: OP_IF :: OP_3 :: OP_3 :: OP_EQUAL :: OP_IF :: OP_5 :: OP_ENDIF :: OP_ELSE :: OP_4 :: OP_ENDIF :: Nil
    val stack2 = runner.run(script2)
    assert(stack2 === List(ByteVector(5)))
  }
  it should "encode/decode simple numbers" in {
    for (i <- -1 to 16) {
      assert(Script.decodeNumber(Script.encodeNumber(i), checkMinimalEncoding = true) === i)
    }
  }
  it should "encode/decode booleans" in {
    assert(Script.castToBoolean(ByteVector.empty) === false)
    assert(Script.castToBoolean(ByteVector(0, 0, 0)) === false)
    assert(Script.castToBoolean(hex"80") === false)
  }
}
