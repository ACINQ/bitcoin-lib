package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.PrivateKey
import org.scalatest.FlatSpec
import scodec.bits.{ByteVector, _}

class CheckLockTimeVerifySpec extends FlatSpec {
  "Bip65" should "let you initiate payment channels" in {

    val previousTx = Transaction.read("0100000001bb4f5a244b29dc733c56f80c0fed7dd395367d9d3b416c01767c5123ef124f82000000006b4830450221009e6ed264343e43dfee2373b925915f7a4468e0bc68216606e40064561e6c097a022030f2a50546a908579d0fab539d5726a1f83cfd48d29b89ab078d649a8e2131a0012103c80b6c289bf0421d010485cec5f02636d18fb4ed0f33bfa6412e20918ebd7a34ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388acf0b0b805000000001976a914807c74c89592e8a260f04b5a3bc63e7bef8c282588ac00000000")
    //val key = SignData(previousTx.txOut(0).publicKeyScript, PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1)
    val key = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1

    val keyAlice = PrivateKey(hex"C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA")
    val pubAlice = keyAlice.publicKey

    val keyBob = PrivateKey(hex"5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C")
    val pubBob = keyBob.publicKey

    // create a pub key script that can be redeemed either:
    // by Alice alone, in a tx which locktime is > 100
    // or by Alice and Bob, anytime
    val scriptPubKey = OP_IF ::
      OP_PUSHDATA(ByteVector(100: Byte)) :: OP_CHECKLOCKTIMEVERIFY :: OP_DROP :: OP_PUSHDATA(pubAlice.value) :: OP_CHECKSIG ::
      OP_ELSE ::
      OP_2 :: OP_PUSHDATA(pubAlice.value) :: OP_PUSHDATA(pubBob.value) :: OP_2 :: OP_CHECKMULTISIG :: OP_ENDIF :: Nil

    // create a tx that sends money to scriptPubKey
    val tx = {
      val tmpTx = Transaction(
        version = 1L,
        txIn = TxIn(OutPoint(previousTx.hash, 0), sequence = 0L, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(amount = 100 sat, publicKeyScript = scriptPubKey) :: Nil,
        lockTime = 100L
      )
      val sig = Transaction.signInput(tmpTx, 0, previousTx.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, key)
      tmpTx.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(key.publicKey) :: Nil)
    }

    Transaction.correctlySpends(tx, Seq(previousTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)


    // now we try to redeem this tx
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val amount = 10000

    // we can redeem this tx with a single signature from Alice, if the lock time of the redeeming tx is >= 100
    val tx1 = {
      val tmpTx = Transaction(
        version = 1L,
        txIn = TxIn(OutPoint(tx.hash, 0), sequence = 0L, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(amount = 100 sat, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
        lockTime = 100L
      )

      val sig = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, keyAlice)

      // our script sig is simple our signature followed by "true"
      val sigScript = OP_PUSHDATA(sig) :: OP_1 :: Nil

      tmpTx.updateSigScript(0, sigScript)
      //tmpTx.copy(txIn = tmpTx.txIn.updated(0, tmpTx.txIn(0).copy(signatureScript = sigScript)))
    }
    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)


    // but we cannot redeem this tx with a single signature from Alice if the lock time of the redeeming tx is < 100
    val tx3 = {
      val tmpTx = Transaction(
        version = 1L,
        txIn = TxIn(OutPoint(tx.hash, 0), sequence = 0L, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(amount = 100 sat, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
        lockTime = 99L
      )

      val sig = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, keyAlice)

      // our script sig is simple our signature followed by "true"
      val sigScript = OP_PUSHDATA(sig) :: OP_1 :: Nil

      tmpTx.updateSigScript(0, sigScript)
      //tmpTx.copy(txIn = tmpTx.txIn.updated(0, tmpTx.txIn(0).copy(signatureScript = sigScript)))
    }

    intercept[RuntimeException] {
      Transaction.correctlySpends(tx3, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
    }

    // we can also redeem this tx with 2 signatures from Alice and Bob
    val tx2 = {
      val tmpTx = Transaction(
        version = 1L,
        txIn = TxIn(OutPoint(tx.hash, 0), sequence = 0L, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(amount = 100 sat, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
        lockTime = 0L
      )

      val sig1 = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, keyAlice)
      val sig2 = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, keyBob)
      val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_0 :: Nil

      tmpTx.updateSigScript(0, sigScript)
    }
    Transaction.correctlySpends(tx2, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
  }
}
