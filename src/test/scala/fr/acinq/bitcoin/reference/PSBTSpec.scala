package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.{BinaryData, PSBT, Transaction}
import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization._

import scala.io.Source
import scala.util.{Failure, Success, Try}

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

    testData.invalid.foreach { invalidPSBT=>
      assert(Try(PSBT.read64(invalidPSBT)).isFailure)
    }

    testData.valid.foreach { case validPSBT =>
      assert(Try(PSBT.read64(validPSBT)) match {
        case Success(_) => true
        //Try again forcing non segwit serialization format (#5 contains this tranaction: 02000000000140420f000000000017a9146e91b72d5593e7d4391e2ff44e91e985c31641f08700000000)
        case Failure(_) => Try(PSBT.read64(validPSBT, 0x40000000L)).isSuccess
      })
    }

  }

}
