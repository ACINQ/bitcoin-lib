package fr.acinq.bitcoin

import fr.acinq.bitcoin.Base58.Prefix
import fr.acinq.bitcoin.Crypto.PrivateKey
import org.scalatest.{FunSuite, Matchers}
import scodec.bits._

class MultisigSpec extends FunSuite with Matchers {
  val key1 = PrivateKey(hex"C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA01")
  val pub1 = key1.publicKey

  val key2 = PrivateKey(hex"5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C01")
  val pub2 = key2.publicKey

  val key3 = PrivateKey(hex"29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C01")
  val pub3 = key3.publicKey

  val redeemScript = Script.write(Script.createMultiSigMofN(2, List(pub1, pub2, pub3)))
  val multisigAddress = Crypto.hash160(redeemScript)

  test("create and sign multisig transactions") {

    // tested with bitcoin core client using command: createmultisig 2 "[\"0394D30868076AB1EA7736ED3BDBEC99497A6AD30B25AFD709CDF3804CD389996A\",\"032C58BC9615A6FF24E9132CEF33F1EF373D97DC6DA7933755BC8BB86DBEE9F55C\",\"02C4D72D99CA5AD12C17C9CFE043DC4E777075E8835AF96F46D8E3CCD929FE1926\"]"
    redeemScript should equal(hex"52210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653ae")

    // 196 = prefix for P2SH adress on testnet
    Base58Check.encode(Prefix.ScriptAddressTestnet, multisigAddress) should equal("2N8epCi6GwVDNYgJ7YtQ3qQ9vGQzaGu6JY4")

    // we want to redeem the first output of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
    // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    val txIn = TxIn(
      OutPoint(ByteVector32(hex"41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea".reverse), 0),
      signatureScript = ByteVector.empty, // empy signature script
      sequence = 0xFFFFFFFFL)

    // and we want to sent the output to our multisig address
    val txOut = TxOut(
      amount = 900000 sat, // 0.009 BTC) satoshi, meaning the fee will be 0.01-0.009 = 0.001
      publicKeyScript = Script.write(OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil))

    // create a tx with empty input signature scripts
    val tx = Transaction(version = 1L, txIn = List(txIn), txOut = List(txOut), lockTime = 0L)

    val priv = PrivateKey.fromBase58("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM", Base58.Prefix.SecretKeyTestnet)._1
    val sig = Transaction.signInput(tx, 0, hex"76a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac", SIGHASH_ALL, txOut.amount, SigVersion.SIGVERSION_BASE, priv)
    val signedTx = tx.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv.publicKey.toUncompressedBin) :: Nil)

    //this works because signature is not randomized
    assert(signedTx.toString == "0100000001ea1df27ca8a897c985f163407e2c20cbc310ca891ca361c207ba8f4b7073e541000000008b483045022100940f7bcb380fb6db698f71928bda8926f76305ff868919e8ef7729647606bf7702200d32f1231860cb7e6777447c4038627bee7f47bc54005f681b62ce71d4a6a7f10141042adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002f9cc4148f603beb0e874facd3a3e68f5d002a65c0d3658452a4e55a57f5c3b768ffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    // the id of this tx on testnet is af416176497f898b1eaf545ecec2a42b833488c2e4324f2cde732f875f2a5b34
  }

  test("spend multisig transaction") {
    //this is the P2SH multisig input transaction
    val previousTx = Transaction.read("0100000001ea1df27ca8a897c985f163407e2c20cbc310ca891ca361c207ba8f4b7073e541000000008b483045022100940f7bcb380fb6db698f71928bda8926f76305ff868919e8ef7729647606bf7702200d32f1231860cb7e6777447c4038627bee7f47bc54005f681b62ce71d4a6a7f10141042adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002f9cc4148f603beb0e874facd3a3e68f5d002a65c0d3658452a4e55a57f5c3b768ffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    val dest = "msCMyGGJ5eRcUgM5SQkwirVQGbGcr9oaYv"
    //priv: 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    // 0.008 BTC) satoshi, meaning the fee will be 0.009-0.008 = 0.001
    val amount = 800000 sat

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = List(TxIn(OutPoint(previousTx, 0), ByteVector.empty, 0xffffffffL)),
      txOut = List(TxOut(
        amount = amount,
        publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
      lockTime = 0L
    )

    // we only need 2 signatures because this is a 2-on-3 multisig
    val sig1 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, key1)
    val sig2 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, key2)

    // OP_0 because of a bug) OP_CHECKMULTISIG
    val scriptSig = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
    val signedTx = tx.updateSigScript(0, scriptSig)

    //this works because signature is not randomized
    assert(signedTx.toString == "0100000001345b2a5f872f73de2c4f32e4c28834832ba4c2ce5e54af1e8b897f49766141af00000000fdfe0000483045022100e5a3c850d7cb8776bfbd3fa4b24ce9bb3514fe96a922449dd14c03f5fa04d6ad022035710c6b9c2922c7b8de02fb674cb61e2c18ea439b190b4f55c14fad1ed89eb801483045022100ec6b1ea37cc5694312f7d5fe72280ef21688d11e00f307fdcc1eff30718e30560220542e02c32e3e392cce7adfc287c72f7f1e51ca73980505c2bebcf0b7b441ff90014c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914801d5eb10d2c1513ba1960fd8893f0ddbbe33bb388ac00000000")

    // the id of this tx on testnet is f137884feb9a951bf9b159432ebb771ec76fa6e7332c06cb8a6b718148f101af
    // redeem the tx
    Transaction.correctlySpends(signedTx, List(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
}
