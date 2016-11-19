package fr.acinq.bitcoin

import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import Base58.Prefix

import scala.util.Random

@RunWith(classOf[JUnitRunner])
class CryptoSpec extends FlatSpec {

  "Crypto" should "import private keys" in {
    // exported from the bitcoin client running in testnet mode
    val address = "mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY"
    val privateKey = "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp"

    val (version, data) = Base58Check.decode(privateKey)
    val publicKey = Crypto.publicKeyFromPrivateKey(data)
    val computedAddress = Base58Check.encode(Prefix.PubkeyAddressTestnet, Crypto.hash160(publicKey))
    assert(computedAddress === address)
  }

  // see https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
  it should "generate public keys from private keys" in {
    val privateKey = fromHexString("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
    val publicKey = Crypto.publicKeyFromPrivateKey(privateKey)
    assert(toHexString(publicKey) === "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6")

    val address = Base58Check.encode(Prefix.PubkeyAddress, Crypto.hash160(publicKey))
    assert(address === "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
  }

  it should "generate public keys from private keys 2" in {
    val privateKey = fromHexString("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
    val publicKey = Crypto.publicKeyFromPrivateKey(privateKey)
    assert(toHexString(publicKey) === "04D7E9DD0C618C65DC2E3972E2AA406CCD34E5E77895C96DC48AF0CB16A1D9B8CE0C0A3E2F4CD494FF54FBE4F5A95B410C0BF022EB2B6F23AE39F40DB79FAA6827".toLowerCase)

    val address = Base58Check.encode(Prefix.PubkeyAddress, Crypto.hash160(publicKey))
    assert(address === "19FgFQGZy47NcGTJ4hfNdGMwS8EATqoa1X")
  }

  it should "sign and verify signatures" in {
    val random = new Random()
    val (_, privateKey) = Base58Check.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")
    val publicKey = Crypto.publicKeyFromPrivateKey(privateKey)
    val data = "this is a test".getBytes("UTF-8")
    val (r, s) = Crypto.sign(data, privateKey.take(32)) // because "compressed" keys have a extra 0x01 at the end
    val encoded = Crypto.encodeSignature(r, s)
    assert(Crypto.verifySignature(data, encoded, publicKey))
  }

  it should "generate deterministic signatures" in {
    // dataset from https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
    val dataset = Seq(
      (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "Satoshi Nakamoto",
        "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
        ),
      ("0000000000000000000000000000000000000000000000000000000000000001",
        "Everything should be made as simple as possible, but not simpler.",
        "3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
        ),
      ("0000000000000000000000000000000000000000000000000000000000000001",
        "All those moments will be lost in time, like tears in rain. Time to die...",
        "30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
        ),
      ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        "Satoshi Nakamoto",
        "3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
        ),
      ("f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
        "Alan Turing",
        "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"),
      ("e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
        "3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6")
    )

    dataset.map {
      case (k, m, s) =>
        val sig: BinaryData = Crypto.encodeSignature(Crypto.sign(Crypto.sha256(BinaryData(m.getBytes("UTF-8"))), BinaryData(k)))
        assert(sig == BinaryData(s))
    }
  }
}
