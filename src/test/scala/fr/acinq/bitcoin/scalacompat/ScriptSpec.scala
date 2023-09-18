package fr.acinq.bitcoin.scalacompat

import com.google.common.io.BaseEncoding
import fr.acinq.bitcoin.Base58.Prefix
import fr.acinq.bitcoin.Base58Check
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import org.scalatest.FlatSpec
import scodec.bits._

class ScriptSpec extends FlatSpec {

  import ScriptSpec._

  it should "parse signature scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c")
    val script = Script.parse(blob)
    val Some(pk) = publicKey(script)
    val hash = Crypto.hash160(pk)
    assert(Base58Check.encode(Prefix.PubkeyAddressTestnet, hash.toArray) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to public key' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac")
    val script = Script.parse(blob)
    assert(Script.isPay2pkh(script))
    val Some(hash) = publicKeyHash(script)
    assert(Base58Check.encode(Prefix.PubkeyAddressTestnet, hash.toArray) === "mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2")
  }
  it should "parse 'pay to script' scripts" in {
    val blob = BaseEncoding.base16().lowerCase().decode("a914a90003b4ddef4be46fc61e7f2167da9d234944e287")
    val script = Script.parse(blob)
    assert(Script.isPay2sh(script))
    val OP_HASH160 :: OP_PUSHDATA(scriptHash, _) :: OP_EQUAL :: Nil = script
    val multisigAddress = Base58Check.encode(Prefix.ScriptAddressTestnet, scriptHash.toArray)
    assert(multisigAddress === "2N8epCi6GwVDNYgJ7YtQ3qQ9vGQzaGu6JY4")
  }
  it should "detect 'pay to script' scripts" in {
    val script = hex"a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787"
    assert(Script.isPayToScript(script))
    assert(Script.isPay2sh(Script.parse(script)))
  }
  it should "detect 'native witness' scripts" in {
    val p2wpkh = Script.pay2wpkh(PublicKey(hex"029da12cdb5b235692b91536afefe5c91c3ab9473d8e43b533836ab456299c8871"))
    assert(Script.isPay2wpkh(p2wpkh))
    assert(Script.isNativeWitnessScript(p2wpkh))
    assert(Script.isNativeWitnessScript(Script.write(p2wpkh)))
    assert(Script.getWitnessVersion(p2wpkh) === Some(0))
    val p2wsh = Script.pay2wsh(hex"a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787")
    assert(Script.isPay2wsh(p2wsh))
    assert(Script.isNativeWitnessScript(p2wsh))
    assert(Script.isNativeWitnessScript(Script.write(p2wsh)))
    assert(Script.getWitnessVersion(p2wsh) === Some(0))
  }
  it should "encode/decode simple numbers" in {
    for (i <- -1 to 16) {
      assert(Script.decodeNumber(Script.encodeNumber(i), checkMinimalEncoding = true) === i)
    }
  }
}

object ScriptSpec {
  /**
   * extract a public key hash from a public key script
   *
   * @param script public key script
   * @return the public key hash wrapped in the script
   */
  def publicKeyHash(script: List[ScriptElt]): Option[ByteVector] = script match {
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: OP_NOP :: Nil => Some(data) // non standard pay to pubkey...
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil => Some(data) // standard pay to pubkey
    case OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUAL :: Nil if data.size == 20 => Some(data) // standard pay to script
    case _ => None
  }

  def publicKeyHash(script: ByteVector): Option[ByteVector] = publicKeyHash(Script.parse(script))

  /**
   * extract a public key from a signature script
   *
   * @param script signature script
   * @return the public key wrapped in the script
   */
  def publicKey(script: List[ScriptElt]): Option[ByteVector] = script match {
    case OP_PUSHDATA(data1, _) :: OP_PUSHDATA(data2, _) :: Nil if data1.length > 2 && data2.length > 2 => Some(data2)
    case OP_PUSHDATA(data, _) :: OP_CHECKSIG :: Nil => Some(data)
    case _ => None
  }
}
