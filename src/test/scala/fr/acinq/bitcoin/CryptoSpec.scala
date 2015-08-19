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
    val (r, s) = Crypto.sign(data, privateKey.take(32), randomize = false) // because "compressed" keys have a extra 0x01 at the end
    val encoded = Crypto.encodeSignature(r, s)
    assert(Crypto.verifySignature(data, encoded, publicKey))
  }
}
