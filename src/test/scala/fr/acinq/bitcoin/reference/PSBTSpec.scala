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


  //TODO check out commit 52d9adcdfbf545cb9a9facb482cb3673578abfa0
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

}
