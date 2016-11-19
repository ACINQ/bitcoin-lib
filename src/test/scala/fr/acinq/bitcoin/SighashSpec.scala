package fr.acinq.bitcoin

import org.scalatest.{FlatSpec, FunSuite}

/**
  * Created by fabrice on 25/10/16.
  */
class SighashSpec extends FunSuite {
  test("SIGHASH_ANYONECANPAY lets you add inputs") {
    val address1 = "moKHwpsxovDtfBJyoXpof21vvWooBExutV"
    val destAmount = 3000000 satoshi

    val address2 = "mvHPesWqLXXy7hntNa7vbAoVwqN5PnrwJd"
    val changeAmount = 1700000 satoshi

    val previousTx = List(
      Transaction.read("0100000001bb4f5a244b29dc733c56f80c0fed7dd395367d9d3b416c01767c5123ef124f82000000006b4830450221009e6ed264343e43dfee2373b925915f7a4468e0bc68216606e40064561e6c097a022030f2a50546a908579d0fab539d5726a1f83cfd48d29b89ab078d649a8e2131a0012103c80b6c289bf0421d010485cec5f02636d18fb4ed0f33bfa6412e20918ebd7a34ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388acf0b0b805000000001976a914807c74c89592e8a260f04b5a3bc63e7bef8c282588ac00000000"),
      Transaction.read("0100000001345b2a5f872f73de2c4f32e4c28834832ba4c2ce5e54af1e8b897f49766141af00000000fdfe0000483045022100e5a3c850d7cb8776bfbd3fa4b24ce9bb3514fe96a922449dd14c03f5fa04d6ad022035710c6b9c2922c7b8de02fb674cb61e2c18ea439b190b4f55c14fad1ed89eb801483045022100ec6b1ea37cc5694312f7d5fe72280ef21688d11e00f307fdcc1eff30718e30560220542e02c32e3e392cce7adfc287c72f7f1e51ca73980505c2bebcf0b7b441ff90014c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914801d5eb10d2c1513ba1960fd8893f0ddbbe33bb388ac00000000")
    )

    val keys = List(
      BinaryData(Base58Check.decode("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs")._2),
      BinaryData(Base58Check.decode("93NJN4mhL21FxRbfHZJ2Cou1YnrJmWNkujmZxeT7CPKauJkGv5g")._2)
    )

    val pub = Crypto.publicKeyFromPrivateKey(keys(0))

    // create a tx that spends the first of our previous tx
    val tx = {
      val tmp = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(previousTx(0), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil) :: Nil,
        txOut = TxOut(600000 satoshi, Script.pay2wpkh(pub)) :: Nil,
        lockTime = 0L
      )
      val sig = Transaction.signInput(tmp, 0, previousTx(0).txOut(0).publicKeyScript, SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(0).txOut(0).amount, SigVersion.SIGVERSION_BASE, keys(0))
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(Crypto.publicKeyFromPrivateKey(keys(0))) :: Nil)
    }

    Transaction.correctlySpends(tx, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // we can now add another input without invalidating the signature above
    val tx1 = {
      val tmp = tx.copy(txIn = tx.txIn :+ TxIn(OutPoint(previousTx(1), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig = Transaction.signInput(tmp, 1, previousTx(1).txOut(0).publicKeyScript, SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(1).txOut(0).amount, SigVersion.SIGVERSION_BASE, keys(1))
      tmp.updateSigScript(1, OP_PUSHDATA(sig) :: OP_PUSHDATA(Crypto.publicKeyFromPrivateKey(keys(1))) :: Nil)
    }

    Transaction.correctlySpends(tx1, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }
}
