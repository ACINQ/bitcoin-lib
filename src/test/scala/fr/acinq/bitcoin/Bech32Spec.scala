package fr.acinq.bitcoin

import org.scalatest.FunSuite
import scodec.bits._

/**
  * Created by fabrice on 19/04/17.
  */
class Bech32Spec extends FunSuite {
  test("valid checksums") {
    val inputs = Seq(
      "A12UEL5L",
      "a12uel5l",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
      "?1ezyfcl"
    )
    val outputs = inputs.map(Bech32.decode)
    assert(outputs.length == inputs.length)
  }

  test("invalid checksums") {
    val inputs = Seq(
      " 1nwldj5",
      "\u007f1axkwrx",
      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "de1lg7wt\u00ff"
    )

    inputs.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }

  test("decode addresses") {
    val inputs = Seq(
      "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" -> "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" -> "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" -> "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
      "BC1SW50QA3JX3S" -> "9002751e",
      "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" -> "8210751e76e8199196d454941c45d1b3a323",
      "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    )
    inputs.map {
      case (address, bin) =>
        val (_, _, bin1) = Bech32.decodeWitnessAddress(address)
        assert(bin1.toHex == bin.substring(4))
    }
  }

  test("create addresses") {
    assert(Bech32.encodeWitnessAddress("bc", 0, hex"751e76e8199196d454941c45d1b3a323f1433bd6") == "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase)
    assert(Bech32.encodeWitnessAddress("tb", 0, hex"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262") == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
    assert(Bech32.encodeWitnessAddress("tb", 0, hex"000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
      "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
      "bc1rw5uspcuh",
      "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
      "bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035",
      "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
      "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
      "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
      "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
      "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
      "bc1gmk9yu"
    )
    addresses.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }

  test("encode lnurl string") {
    val inputs = Seq(
      // example lnurl string taken from https://github.com/fiatjaf/lnurl-rfc
      "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df" -> "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS"
    )
    inputs.map {
      case (uri, expected) =>
        val bytes = Bech32.eight2five(uri.getBytes)
        val encodedLnurl = Bech32.encode("lnurl", bytes)
        assert(encodedLnurl == expected.toLowerCase)
    }
  }

  test("decode lnurl string") {
    val inputs = Seq(
      // example lnurl string taken from https://github.com/fiatjaf/lnurl-rfc
      "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS" -> "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df"
    )
    inputs.map {
      case (encodedLnurl, expected) =>
        val decoded = Bech32.decode(encodedLnurl);
        val decodedLnurl = new String(Bech32.five2eight(decoded._2));
        assert(decodedLnurl equals expected)
    }
  }
}
