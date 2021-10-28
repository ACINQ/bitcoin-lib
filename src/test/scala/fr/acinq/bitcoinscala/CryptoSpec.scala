package fr.acinq.bitcoinscala

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

import fr.acinq.bitcoinscala.Base58.Prefix
import fr.acinq.bitcoinscala.Crypto._
import org.scalatest.FlatSpec
import scodec.bits._

import scala.io.Source
import scala.util.Random

class CryptoSpec extends FlatSpec {

  "Crypto" should "import private keys" in {
    // exported from the bitcoin client running in testnet mode
    val address = "mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY"
    val privateKey = "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp"

    val (version, data) = Base58Check.decode(privateKey)
    val priv = PrivateKey(data)
    val publicKey = priv.publicKey
    val computedAddress = Base58Check.encode(Prefix.PubkeyAddressTestnet, Crypto.hash160(publicKey.value))
    assert(computedAddress === address)
  }

  // see https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
  it should "generate public keys from private keys" in {
    val privateKey = PrivateKey(hex"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
    val publicKey = privateKey.publicKey
    assert(publicKey.toUncompressedBin === hex"0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6")

    val address = Base58Check.encode(Prefix.PubkeyAddress, Crypto.hash160(publicKey.toUncompressedBin))
    assert(address === "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
  }

  it should "generate public keys from private keys 2" in {
    val privateKey = PrivateKey(hex"BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
    val publicKey = privateKey.publicKey
    assert(publicKey.toUncompressedBin === hex"04D7E9DD0C618C65DC2E3972E2AA406CCD34E5E77895C96DC48AF0CB16A1D9B8CE0C0A3E2F4CD494FF54FBE4F5A95B410C0BF022EB2B6F23AE39F40DB79FAA6827")

    val address = Base58Check.encode(Prefix.PubkeyAddress, Crypto.hash160(publicKey.toUncompressedBin))
    assert(address === "19FgFQGZy47NcGTJ4hfNdGMwS8EATqoa1X")
  }

  it should "validate public key at instantiation" in {
    intercept[Throwable] { // can be IllegalArgumentException or AssertFailException depending on whether bouncycastle or libsecp256k1 is used
      // by default we check
      PublicKey(hex"04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", checkValid = true)
    }
    // key is invalid but we don't check it
    PublicKey(hex"04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", checkValid = false)
  }

  it should "allow unsafe initialization of public keys" in {
    val privateKey = PrivateKey(hex"BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
    val publicKey = privateKey.publicKey
    val rawCompressed = publicKey.value
    val rawUncompressed = publicKey.toUncompressedBin
    assert(rawCompressed.size == 33)
    assert(rawUncompressed.size == 65)
    val publicKeyCompressed1 = PublicKey.fromBin(rawCompressed)
    val publicKeyCompressed2 = PublicKey.fromBin(rawUncompressed)
    assert(publicKey === publicKeyCompressed1)
    assert(publicKey === publicKeyCompressed2)
  }

  it should "sign and verify signatures" in {
    val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val publicKey = privateKey.publicKey
    val data = Crypto.sha256(ByteVector("this is a test".getBytes("UTF-8")))
    val sig = Crypto.sign(data, privateKey)
    assert(Crypto.verifySignature(data, sig, publicKey))
  }

  it should "generate deterministic signatures" in {
    // dataset from https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
    val dataset = Seq(
      (
        hex"0000000000000000000000000000000000000000000000000000000000000001",
        "Satoshi Nakamoto",
        hex"3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
      ),
      (
        hex"0000000000000000000000000000000000000000000000000000000000000001",
        "Everything should be made as simple as possible, but not simpler.",
        hex"3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
      ),
      (
        hex"0000000000000000000000000000000000000000000000000000000000000001",
        "All those moments will be lost in time, like tears in rain. Time to die...",
        hex"30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
      ),
      (
        hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        "Satoshi Nakamoto",
        hex"3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
      ),
      (
        hex"f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
        "Alan Turing",
        hex"304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
      ),
      (
        hex"e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
        hex"3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6")
    )

    dataset.map {
      case (k, m, s) =>
        val sig: ByteVector = Crypto.compact2der(Crypto.sign(Crypto.sha256(ByteVector.view(m.getBytes("UTF-8"))), PrivateKey(k)))
        assert(sig == s)
    }
  }

  def serialize[T](t: T): ByteVector = {
    val bos = new ByteArrayOutputStream()
    val oos = new ObjectOutputStream(bos)
    oos.writeObject(t)
    ByteVector.view(bos.toByteArray)
  }

  def deserialize[T](input: ByteVector): T = {
    val bis = new ByteArrayInputStream(input.toArray)
    val osi = new ObjectInputStream(bis)
    osi.readObject().asInstanceOf[T]
  }

  it should "serialize points and scalars" in {
    val secret = PrivateKey(hex"0101010101010101010101010101010101010101010101010101010101010101")
    val point = secret.publicKey

    assert(deserialize[PrivateKey](serialize(secret)) == secret)
    assert(deserialize[PublicKey](serialize(point)) == point)
  }

  it should "serialize public and private keys" in {
    val priv = PrivateKey(hex"0101010101010101010101010101010101010101010101010101010101010101")
    val pub = priv.publicKey

    assert(deserialize[PrivateKey](serialize(priv)) == priv)
    assert(deserialize[PublicKey](serialize(pub)) == pub)
  }

  it should "recover public keys from signatures (basic test)" in {
    val priv = PrivateKey(hex"0101010101010101010101010101010101010101010101010101010101010101")
    val message = hex"0202020202020202020202020202020202020202020202020202020202020202"
    val pub = priv.publicKey
    val sig64 = Crypto.sign(message, priv)
    val (pub1, pub2) = recoverPublicKey(sig64, message)

    assert(verifySignature(message, sig64, pub1))
    assert(verifySignature(message, sig64, pub2))
    assert(pub == pub1 || pub == pub2)
  }

  it should "recover public keys from signatures (secp256k1 test)" in {
    val stream = classOf[CryptoSpec].getResourceAsStream("/recid.txt")
    val iterator = Source.fromInputStream(stream).getLines()
    var priv: PrivateKey = null
    var message: ByteVector = null
    var pub: PublicKey = null
    var sig: ByteVector = null
    var recid: Int = -1
    while (iterator.hasNext) {
      val line = iterator.next()
      val Array(lhs, rhs) = line.split(" = ")
      lhs match {
        case "privkey" => priv = PrivateKey(ByteVector.fromValidHex(rhs))
        case "message" => message = ByteVector.fromValidHex(rhs)
        case "pubkey" => pub = PublicKey(ByteVector.fromValidHex(rhs))
        case "sig" => sig = ByteVector.fromValidHex(rhs)
        case "recid" =>
          recid = rhs.toInt
          assert(priv.publicKey == pub)
          val sig64 = Crypto.sign(message, priv)
          val check = recoverPublicKey(sig64, message, recid)
          assert(check == pub)
      }
    }
  }

  it should "recover public keys from signatures (random tests)" in {
    val random = new Random()
    val privbytes = new Array[Byte](32)
    val message = new Array[Byte](32)
    for (i <- 0 until 100) {
      random.nextBytes(privbytes)
      random.nextBytes(message)

      val bytesMessage = ByteVector.view(message)

      val priv = PrivateKey(bytesMessage)
      val pub = priv.publicKey
      val sig64 = Crypto.sign(ByteVector.view(message), priv)
      val (pub1, pub2) = recoverPublicKey(sig64, bytesMessage)

      assert(verifySignature(bytesMessage, sig64, pub1))
      assert(verifySignature(bytesMessage, sig64, pub2))
      assert(pub == pub1 || pub == pub2)
    }
  }
}
