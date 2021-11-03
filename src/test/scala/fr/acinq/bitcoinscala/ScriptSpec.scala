package fr.acinq.bitcoinscala

import com.google.common.io.BaseEncoding
import fr.acinq.bitcoinscala.Base58.Prefix
import fr.acinq.bitcoinscala.Crypto.PublicKey
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
  it should "encode/decode simple numbers" in {
    for (i <- -1 to 16) {
      assert(Script.decodeNumber(Script.encodeNumber(i), checkMinimalEncoding = true) === i)
    }
  }
}
