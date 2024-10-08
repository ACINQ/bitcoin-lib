package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin.SigHash._
import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import fr.acinq.bitcoin.{Base58, ScriptFlags, SigVersion}
import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
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
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2pkh(publicKeys.head)) :: Nil, lockTime = 0),
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2pkh(publicKeys(1))) :: Nil, lockTime = 0)
    )

    // create a tx with no inputs
    val tx = Transaction(version = 2, txIn = Nil, txOut = TxOut(80 millibtc, Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys))) :: Nil, lockTime = 0L)

    // add an input
    val tx1 = {
      val tmp = tx.addInput(TxIn(OutPoint(previousTx.head, 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig = tmp.signInput(0, Script.pay2pkh(publicKeys.head), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(0).txOut.head.amount, SigVersion.SIGVERSION_BASE, privateKeys.head)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKeys.head.value) :: Nil)

    }
    tx1.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // add another input: the first input's sig si still valid !
    val tx2 = {
      val tmp = tx1.addInput(TxIn(OutPoint(previousTx(1), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig: ByteVector = tmp.signInput(1, Script.pay2pkh(publicKeys(1)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(1).txOut.head.amount, SigVersion.SIGVERSION_BASE, privateKeys(1))
      tmp.updateSigScript(1, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKeys(1).value) :: Nil)
    }
    tx2.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // but I cannot change the tx output
    val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut.head.copy(amount = 40 millibtc)))
    intercept[RuntimeException] {
      tx3.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
  }

  test("SIGHASH_ANYONECANPAY lets you add inputs (SEGWIT version") {
    val privateKeys = List(
      PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1,
      PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
    )

    val publicKeys = privateKeys.map(_.publicKey)

    val previousTx = Seq(
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2wpkh(publicKeys.head)) :: Nil, lockTime = 0),
      Transaction(version = 2, txIn = Nil, txOut = TxOut(42 millibtc, Script.pay2wpkh(publicKeys(1))) :: Nil, lockTime = 0)
    )

    // create a tx with no inputs
    val tx = Transaction(version = 2, txIn = Nil, txOut = TxOut(80 millibtc, Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys))) :: Nil, lockTime = 0L)

    // add an input
    val tx1 = {
      val tmp = tx.addInput(TxIn(OutPoint(previousTx.head, 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig = tmp.signInput(0, Script.pay2pkh(publicKeys.head), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(0).txOut.head.amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys.head)
      tmp.updateWitness(0, ScriptWitness(sig :: publicKeys.head.value :: Nil))
    }
    tx1.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // add another input: the first input's sig si still valid !
    val tx2 = {
      val tmp = tx1.addInput(TxIn(OutPoint(previousTx(1), 0), sequence = 0xFFFFFFFFL, signatureScript = Nil))
      val sig = tmp.signInput(1, Script.pay2pkh(publicKeys(1)), SIGHASH_ALL | SIGHASH_ANYONECANPAY, previousTx(1).txOut.head.amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys(1))
      tmp.updateWitness(1, ScriptWitness(sig :: publicKeys(1).value :: Nil))
    }
    tx2.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // but I cannot change the tx output
    val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut.head.copy(amount = 40 millibtc)))
    intercept[RuntimeException] {
      tx3.correctlySpends(previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
  }
}
