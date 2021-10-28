package fr.acinq.bitcoinscala

import org.scalatest.FunSuite
import scodec.bits._

/**
 * Created by fabrice on 19/04/17.
 */
class Bech32Spec extends FunSuite {

  test("valid checksums") {
    val inputs = Seq(
      // Bech32
      "A12UEL5L",
      "a12uel5l",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
      "?1ezyfcl",
      // Bech32m
      "A1LQFN3A",
      "a1lqfn3a",
      "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
      "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
      "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
      "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
      "?1v759aa",
    )
    val outputs = inputs.map(Bech32.decode)
    assert(outputs.length == inputs.length)
  }

  test("invalid checksums") {
    val inputs = Seq(
      // Bech32
      " 1nwldj5",
      "\u007f1axkwrx",
      "\u00801eym55h",
      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "de1lg7wt\u00ff",
      "A1G7SGD8",
      "10a06t8",
      "1qzzfhee",
      // Bech32m
      "\u00201xj0phk",
      "\u007F1g6xzxy",
      "\u00801vctc34",
      "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
      "qyrz8wqd2c9m",
      "1qyrz8wqd2c9m",
      "y1b0jsk6g",
      "lt1igcx5c0",
      "in1muywd",
      "mm1crxm3i",
      "au1s5cgom",
      "M1VUXWEZ",
      "16plkw9",
      "1p2gdwpf"
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
      "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y" -> "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
      "BC1SW50QGDZ25J" -> "6002751e",
      "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs" -> "5210751e76e8199196d454941c45d1b3a323",
      "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c" -> "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" -> "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    inputs.map {
      case (address, bin) =>
        val (_, _, bin1) = Bech32.decodeWitnessAddress(address)
        assert(bin1.toHex == bin.substring(4))
    }
  }

  test("create addresses") {
    assert(Bech32.encodeWitnessAddress("bc", 0, hex"751e76e8199196d454941c45d1b3a323f1433bd6") == "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase)
    assert(computeScriptAddress(Block.LivenetGenesisBlock.hash, hex"0014751e76e8199196d454941c45d1b3a323f1433bd6") == "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase)
    assert(Bech32.encodeWitnessAddress("bc", 1, hex"751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6") == "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")
    assert(computeScriptAddress(Block.LivenetGenesisBlock.hash, hex"5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6") == "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")
    assert(Bech32.encodeWitnessAddress("bc", 1, hex"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") == "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    assert(computeScriptAddress(Block.LivenetGenesisBlock.hash, hex"512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") == "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    assert(Bech32.encodeWitnessAddress("tb", 0, hex"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262") == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
    assert(computeScriptAddress(Block.TestnetGenesisBlock.hash, hex"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262") == "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
    assert(Bech32.encodeWitnessAddress("tb", 0, hex"000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")
    assert(computeScriptAddress(Block.TestnetGenesisBlock.hash, hex"0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")
    assert(Bech32.encodeWitnessAddress("tb", 1, hex"000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
    assert(computeScriptAddress(Block.TestnetGenesisBlock.hash, hex"5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
  }

  test("create invalid addresses") {
    val inputs = Seq(
      // invalid segwit v0 program length
      hex"001376e8199196d454941c45d1b3a323f1433bd6a4",
      hex"0015751e76e8199196d454941c45d1b3a323f1433bd6a4",
      hex"0019143c8c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      hex"00211863143c8c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      // invalid segwit v1-16 program length
      hex"5101ff",
      hex"5501aa",
      hex"51290000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      hex"57290000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      // invalid leading opcode
      hex"5028751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
      hex"6128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    )
    inputs.map(script => {
      Seq(Block.LivenetGenesisBlock.hash, Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash).foreach(chainHash => {
        intercept[Exception] {
          computeScriptAddress(chainHash, script)
        }
      })
    })
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      // Bech32
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
      "bc1gmk9yu",
      // Bech32m
      "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
      "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
      "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
      "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
      "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
      "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
      "bc1pw5dgrnzv",
      "bc1pw5dgrnzv",
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
      "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
      "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
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
        val encodedLnurl = Bech32.encode("lnurl", bytes, Bech32.Bech32Encoding)
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
        val (_, decoded, encoding) = Bech32.decode(encodedLnurl)
        assert(encoding === Bech32.Bech32Encoding)
        val decodedLnurl = new String(Bech32.five2eight(decoded))
        assert(decodedLnurl === expected)
    }
  }

}
