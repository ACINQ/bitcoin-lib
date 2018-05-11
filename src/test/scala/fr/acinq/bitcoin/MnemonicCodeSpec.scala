package fr.acinq.bitcoin

import java.io.InputStreamReader

import org.json4s.DefaultFormats
import org.json4s.jackson.JsonMethods
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

import scala.util.Random

object MnemonicCodeSpec {

  case class TestVectors(english: Array[Array[String]])

}

@RunWith(classOf[JUnitRunner])
class MnemonicCodeSpec extends FunSuite {

  import MnemonicCode._
  import MnemonicCodeSpec._

  test("reference tests") {
    implicit val format = DefaultFormats

    val stream = classOf[MnemonicCodeSpec].getResourceAsStream("/bip39_vectors.json")
    val vectors = JsonMethods.parse(new InputStreamReader(stream)).extract[TestVectors]
    vectors.english.map(_ match {
      case Array(raw, mnemonics, seed ,xprv) =>
        assert(toMnemonics(BinaryData(raw)).mkString(" ") === mnemonics)
        assert(toSeed(toMnemonics(BinaryData(raw)), "TREZOR") === BinaryData(seed))
        val master = DeterministicWallet.generate(BinaryData(seed))
        assert(DeterministicWallet.encode(master, DeterministicWallet.xprv) == xprv)
    })
  }

  test("validate mnemonics(valid)") {
    val random = new Random()
    for (i <- 0 to 100) {
      for (length <- Seq(16, 20, 24, 28, 32, 36, 40)) {
        val entropy = new Array[Byte](length)
        random.nextBytes(entropy)
        val mnemonics = MnemonicCode.toMnemonics(entropy)
        MnemonicCode.validate(mnemonics)
      }
    }
  }

  test("validate mnemonics (invalid)") {
    val invalidMnemonics = Seq(
      "",
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow", // one word missing
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog fog", // one extra word
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fig" // wrong word
    )
    invalidMnemonics.map(mnemonics => {
      intercept[RuntimeException] {
        MnemonicCode.validate(mnemonics)
      }
    })
  }
}
