package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.{BinaryData, PSBT, Transaction}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization._

import scala.io.Source
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class PSBTSpec extends FlatSpec {

  implicit val format = DefaultFormats

  case class PSBTTestData(
    invalid: Seq[String],
    valid: Seq[String]
  )

  "PSBT" should "pass the reference tests" in {

    val testData = read[PSBTTestData](
      Source.fromFile("src/test/resources/data/psbt_test_data.json").bufferedReader
    )

    testData.invalid.zipWithIndex.foreach { case (invalidPSBT, index )=>
      println(s"Reading invalidPSBT #$index")
      assert(Try(PSBT.read64(invalidPSBT)).isFailure)
    }

    testData.valid.foreach { validPSBT =>
      assert(Try(PSBT.read64(validPSBT)).isSuccess)
    }

  }

}
