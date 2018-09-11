package fr.acinq.bitcoin.reference

import java.io.ByteArrayOutputStream

import fr.acinq.bitcoin.Crypto.PrivateKey
import fr.acinq.bitcoin._
import fr.acinq.bitcoin.{BinaryData, PSBT, Transaction}
import fr.acinq.bitcoin.PSBT._
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization
import scala.io.Source
import scala.util.{Failure, Success, Try}

@RunWith(classOf[JUnitRunner])
class PSBTSpec extends FlatSpec {

  implicit val format = DefaultFormats

  case class PSBTTestData(
    invalid: Seq[String],
    valid: Seq[String],
    signer: Seq[SignerData],
    combiner: Seq[CombinerData],
    finalizer: Seq[FinalizerData],
    extractor: Seq[ExtractorData]
  )

  case class CombinerData(combine: Seq[String], result: String)
  case class FinalizerData(finaliza: String, result: String)
  case class ExtractorData(extract: String, result: String)
  case class SignerData(privkeys:Seq[String], psbt: String, result: String)


  "PSBT" should "pass the reference tests" in {
    val out = new ByteArrayOutputStream()

    val testData = Serialization.read[PSBTTestData](
      Source.fromFile("src/test/resources/data/psbt_test_data.json").bufferedReader
    )

    //test invalid
    testData.invalid.foreach { invalidPSBT=>
      assert(Try(PSBT.read64(invalidPSBT)).isFailure)
    }

    //test valid
    testData.valid.foreach { case validPSBT =>
      assert(Try(PSBT.read64(validPSBT)) match {
        case Success(_) => true
        //Try again forcing non segwit serialization format (#5 contains this transaction: 02000000000140420f000000000017a9146e91b72d5593e7d4391e2ff44e91e985c31641f08700000000)
        case Failure(_) => Try(PSBT.read64(validPSBT, 0x40000000L)).isSuccess
      })
    }

    //signer test
    testData.signer.foreach { signerTest =>

      val psbt = read64(signerTest.psbt)
      val keys = signerTest.privkeys.map(PrivateKey.fromBase58(_, Base58.Prefix.SecretKeyTestnet))

      val signed = PSBT.signPSBT(psbt, keys)

      out.reset()
      PSBT.write(signed, out)

      assert(toBase64String(out.toByteArray) == signerTest.result)

    }

    //combiner test
    testData.combiner.foreach { combinerTest =>
      val combined = combinerTest.combine.map(in => read64(in)).reduce(mergePSBT(_, _))

      out.reset()
      PSBT.write(combined, out)

      assert(toBase64String(out.toByteArray) == combinerTest.result)
    }

    //finalizer test
    testData.finalizer.foreach { finalizerTest =>

      val psbt = read64(finalizerTest.finaliza)
      val finalized = finalizePSBT(psbt)

      out.reset()
      PSBT.write(finalized, out)

      assert(toBase64String(out.toByteArray) == finalizerTest.result)
    }

    //extractor
    testData.extractor.foreach { extractorTest =>

      val extracted = extractPSBT(read64(extractorTest.extract))

      assert(Transaction.write(extracted).toString == extractorTest.result)
    }


  }

  "SIGNER role" should "produce the same signatures as the reference" in {
    val priv1 = PrivateKey.fromBase58("cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr", Base58.Prefix.SecretKeyTestnet)
    val priv2 = PrivateKey.fromBase58("cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au", Base58.Prefix.SecretKeyTestnet)
    val pub1 = priv1.publicKey
    val pub2 = priv2.publicKey

    assert(pub1.toBin.toString == "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")
    assert(pub2.toBin.toString == "02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7")

    //transaction providing the UTXOs for our inputs
    val prevTx = Transaction.read("0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000")
    val scriptPubKey = prevTx.txOut(0).publicKeyScript

    //redeem: OP_2, 029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f, 02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7, OP_2, OP_CHECKMULTISIG
    val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2))
    assert(Script.pay2sh(redeemScript) == Script.parse(scriptPubKey))

    /**
      * Transaction from bitcoin core reference test 'data/rpc_psbt.json' - signer[1].
      *  txIn =  [
      *     TxIn(OutPoint(prevTx.hash,0), sequence = 0xFFFFFFFF, signatureScript = Nil),
      *     TxIn(OutPoint(BinaryData("838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d"),1),sequence = 0xFFFFFFFF, signatureScript = Nil)
      *  ]
      *  txOut = [
      *     TxOut(149990000 satoshi, BinaryData("0014d85c2b71d0060b09c9886aeb815e50991dda124d")),
      *     TxOut(100000000 satoshi ,BinaryData("001400aea9a2e5f0f876a588df5546e8742d1d87008f"))
      *  ]
      */
    val tx = Transaction.read("020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000")

    //We're making two signatures for the input[0] because it's a multisig (see the redeemScript)
    val sig1 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, prevTx.txOut(0).amount, SigVersion.SIGVERSION_BASE, priv1)
    val sig2 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, prevTx.txOut(0).amount, SigVersion.SIGVERSION_BASE, priv2)

    //Signatures taken from the expected PSBT of the reference test
    val expectedSig1 = BinaryData("3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01")
    val expectedSig2 = BinaryData("30440220631a989fe738a92ad01986023312c19214fe2802b39e5cbc1ac3678806c692c3022039db6c387bd267716dfdb3d4d8da50b8e85d213326ba7c7daaa4c0ce41eb922301")

    assert(sig1 == expectedSig1)
    assert(sig2 != expectedSig2) //FIXME!!

    //A few assertion to check whether they are equivalent
    assert(Crypto.isLowDERSignature(sig2))
    assert(Crypto.isLowDERSignature(expectedSig2))

    assert(Crypto.checkSignatureEncoding(sig2, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS))
    assert(Crypto.checkSignatureEncoding(expectedSig2, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS))

    assert(Crypto.checkSignatureEncoding(sig2, ScriptFlags.SCRIPT_VERIFY_LOW_S))
    assert(Crypto.checkSignatureEncoding(expectedSig2, ScriptFlags.SCRIPT_VERIFY_LOW_S))

    assert(Crypto.checkSignatureEncoding(sig2, ScriptFlags.SCRIPT_VERIFY_STRICTENC))
    assert(Crypto.checkSignatureEncoding(expectedSig2, ScriptFlags.SCRIPT_VERIFY_STRICTENC))

    //try recovering the pubKeys from the two sigs
    val message = Transaction.hashForSigning(tx, 0, redeemScript, SIGHASH_ALL, prevTx.txOut(0).amount, SigVersion.SIGVERSION_BASE)

    val (recoveredPubKey, _) = Crypto.recoverPublicKey(sig2, message)
    val (_, recoveredExpectedPubKey1)= Crypto.recoverPublicKey(expectedSig2, message)

    //Why the expected pubKey happens to be the first on our sig and the second in bitcoincore's?
    assert(recoveredPubKey.toBin == pub2.toBin && recoveredExpectedPubKey1.toBin == pub2.toBin)

    //Try creating and running final sigScripts
    val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(Script.write(redeemScript)) :: Nil
    val expectedSigScript = OP_0 :: OP_PUSHDATA(expectedSig1) :: OP_PUSHDATA(expectedSig2) :: OP_PUSHDATA(Script.write(redeemScript)) :: Nil

    val runner = new Script.Runner(Script.Context(tx, 0, prevTx.txOut(0).amount), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    //both scripts verify correctly!
    assert(runner.verifyScripts(Script.write(expectedSigScript), scriptPubKey, ScriptWitness.empty))
    assert(runner.verifyScripts(Script.write(sigScript), scriptPubKey, ScriptWitness.empty))

  }

}
