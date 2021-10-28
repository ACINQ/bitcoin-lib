package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.Crypto.PrivateKey
import org.scalatest.FunSuite
import scodec.bits.ByteVector

/**
  * Created by fabrice on 25/10/16.
  */
class SighashSpec extends FunSuite {
  test("SIGHASH_ANYONECANPAY lets you add inputs") {
    val privateKeys = List(
      PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1,
      PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
    )

    val publicKeys = privateKeys.map(_.publicKey)

    val previousTx = Seq(
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2pkh(publicKeys(0))) :: Nil, lockTime = 0),
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2pkh(publicKeys(1))) :: Nil, lockTime = 0)
    )

    // create a tx with no inputs
    val tx = Transaction(version = 2, txIn = Nil, txOut = TxOut(80 millibtc, Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys))) :: Nil, lockTime = 0L)

    // add an input
    val tx1 = {
      val tmp = tx.addInput(TxIn(OutPoint(previousTx(0), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig: ByteVector = Transaction.signInput(tmp, 0, Script.pay2pkh(publicKeys(0)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(0).txOut(0).amount, SigVersion.SIGVERSION_BASE, privateKeys(0))
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKeys(0).value) :: Nil)

    }
    Transaction.correctlySpends(tx1, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // add another input: the first input's sig si still valid !
    val tx2 = {
      val tmp = tx1.addInput(TxIn(OutPoint(previousTx(1), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig: ByteVector = Transaction.signInput(tmp, 1, Script.pay2pkh(publicKeys(1)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(1).txOut(0).amount, SigVersion.SIGVERSION_BASE, privateKeys(1))
      tmp.updateSigScript(1, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKeys(1).value) :: Nil)
    }
    Transaction.correctlySpends(tx2, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // but I cannot change the tx output
    val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut(0).copy(amount = 40 millibtc)))
    intercept[RuntimeException] {
      Transaction.correctlySpends(tx3, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
  }

  test("SIGHASH_ANYONECANPAY lets you add inputs (SEGWIT version") {
    val privateKeys = List(
      PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1,
      PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
    )

    val publicKeys = privateKeys.map(_.publicKey)

    val previousTx = Seq(
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2wpkh(publicKeys(0))) :: Nil, lockTime = 0),
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2wpkh(publicKeys(1))) :: Nil, lockTime = 0)
    )

    // create a tx with no inputs
    val tx = Transaction(version = 2, txIn = Nil, txOut = TxOut(80 millibtc, Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys))) :: Nil, lockTime = 0L)

    // add an input
    val tx1 = {
      val tmp = tx.addInput(TxIn(OutPoint(previousTx(0), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig: ByteVector = Transaction.signInput(tmp, 0, Script.pay2pkh(publicKeys(0)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(0).txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys(0))
      tmp.updateWitness(0, ScriptWitness(sig :: publicKeys(0).value :: Nil))
    }
    Transaction.correctlySpends(tx1, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // add another input: the first input's sig si still valid !
    val tx2 = {
      val tmp = tx1.addInput(TxIn(OutPoint(previousTx(1), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig: ByteVector = Transaction.signInput(tmp, 1, Script.pay2pkh(publicKeys(1)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(1).txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys(1))
      tmp.updateWitness(1, ScriptWitness(sig :: publicKeys(1).value :: Nil))
    }
    Transaction.correctlySpends(tx2, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // but I cannot change the tx output
    val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut(0).copy(amount = 40 millibtc)))
    intercept[RuntimeException] {
      Transaction.correctlySpends(tx3, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
  }
}
