package fr.acinq.bitcoin

import org.scalatest.FlatSpec
import scodec.bits._

import java.math.BigInteger
import java.nio.ByteOrder
import scala.util.Random

class DeterministicWalletSpec extends FlatSpec {

  import Protocol._
  import fr.acinq.bitcoin.DeterministicWallet._

  // these tests are the "official" ones (see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

  "Deterministic Wallet" should "generate and derive keys (test vector #1)" in {
    val m = generate(hex"000102030405060708090a0b0c0d0e0f")
    assert(encode(m, xprv) === "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

    val m_pub = publicKey(m)
    assert(encode(m_pub, xpub) === "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert(fingerprint(m) === 876747070)

    val m0h = derivePrivateKey(m, hardened(0))
    assert(encode(m0h, xprv) === "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    val m0h_pub = publicKey(m0h)
    assert(encode(m0h_pub, xpub) === "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

    val m0h_1 = derivePrivateKey(m0h, 1L)
    assert(encode(m0h_1, xprv) === "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
    val m0h_1_pub = publicKey(m0h_1)
    assert(encode(m0h_1_pub, xpub) === "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

    // check that we can also derive this public key from the parent's public key
    val m0h_1_pub1 = derivePublicKey(m0h_pub, 1L)
    assert(encode(m0h_1_pub1, xpub) === "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

    val m0h_1_2h = derivePrivateKey(m0h_1, hardened(2))
    assert(encode(m0h_1_2h, xprv) === "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
    val m0h_1_2h_pub = publicKey(m0h_1_2h)
    assert(encode(m0h_1_2h_pub, xpub) === "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")
    intercept[IllegalArgumentException] {
      derivePublicKey(m0h_1_pub, hardened(2))
    }

    val m0h_1_2h_2 = derivePrivateKey(m0h_1_2h, 2)
    assert(encode(m0h_1_2h_2, xprv) === "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
    val m0h_1_2h_2_pub = publicKey(m0h_1_2h_2)
    assert(encode(m0h_1_2h_2_pub, xpub) === "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
    val m0h_1_2h_2_pub1 = derivePublicKey(m0h_1_2h_pub, 2)
    assert(encode(m0h_1_2h_2_pub1, xpub) === "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

    val m0h_1_2h_2_1000000000 = derivePrivateKey(m0h_1_2h_2, 1000000000L)
    assert(encode(m0h_1_2h_2_1000000000, xprv) === "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
    val m0h_1_2h_2_1000000000_pub = publicKey(m0h_1_2h_2_1000000000)
    assert(encode(m0h_1_2h_2_1000000000_pub, xpub) === "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

    assert(encode(derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: 2L :: 1000000000L :: Nil), xprv) === "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
  }

  it should "generate and derive keys (test vector #2)" in {
    val m = generate(hex"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    assert(encode(m, xprv) === "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")

    val m_pub = publicKey(m)
    assert(encode(m_pub, xpub) === "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

    val m0 = derivePrivateKey(m, 0L)
    assert(encode(m0, xprv) === "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
    val m0_pub = publicKey(m0)
    assert(encode(m0_pub, xpub) === "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

    val m0_2147483647h = derivePrivateKey(m0, hardened(2147483647))
    assert(encode(m0_2147483647h, xprv) === "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
    val m0_2147483647h_pub = publicKey(m0_2147483647h)
    assert(encode(m0_2147483647h_pub, xpub) === "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

    val m0_2147483647h_1 = derivePrivateKey(m0_2147483647h, 1)
    assert(encode(m0_2147483647h_1, xprv) === "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
    val m0_2147483647h_1_pub = publicKey(m0_2147483647h_1)
    assert(encode(m0_2147483647h_1_pub, xpub) === "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

    val m0_2147483647h_1_2147483646h = derivePrivateKey(m0_2147483647h_1, hardened(2147483646))
    assert(encode(m0_2147483647h_1_2147483646h, xprv) === "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
    val m0_2147483647h_1_2147483646h_pub = publicKey(m0_2147483647h_1_2147483646h)
    assert(encode(m0_2147483647h_1_2147483646h_pub, xpub) === "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

    val m0_2147483647h_1_2147483646h_2 = derivePrivateKey(m0_2147483647h_1_2147483646h, 2)
    assert(m0_2147483647h_1_2147483646h_2.path.toString === "m/0/2147483647'/1/2147483646'/2")
    assert(encode(m0_2147483647h_1_2147483646h_2, xprv) === "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
    val m0_2147483647h_1_2147483646h_2_pub = publicKey(m0_2147483647h_1_2147483646h_2)
    assert(encode(m0_2147483647h_1_2147483646h_2_pub, xpub) === "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
  }

  it should "generate and derive keys (test vector #3)" in {
    val m = generate(hex"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    assert(encode(m, xprv) === "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
    assert(encode(publicKey(m), xpub) == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")
    assert(encode(derivePrivateKey(m, hardened(0)), xprv) === "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
    assert(encode(publicKey(derivePrivateKey(m, hardened(0))), xpub) == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")
  }

  it should "generate and derive keys (test vector #4)" in {
    val m = generate(hex"3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    assert(encode(m, xprv) === "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv")
    assert(encode(publicKey(m), xpub) === "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa")
    val m_0h = derivePrivateKey(m, hardened(0))
    assert(m_0h.privateKey.value.head === 0) // private key starts with 0x00
    assert(encode(m_0h, xprv) === "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G")
    assert(encode(publicKey(m_0h), xpub) === "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m")
    val m_0h_1h = derivePrivateKey(m_0h, hardened(1))
    assert(encode(m_0h_1h, xprv) === "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1")
    assert(encode(publicKey(m_0h_1h), xpub) === "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt")
  }

  it should "be possible to go up the private key chain if you have the master pub key and a child private key!!" in {
    val m = generate(hex"000102030405060708090a0b0c0d0e0f")
    assert(encode(m, xprv) === "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    val k = new BigInteger(1, m.secretkeybytes.toArray) // k is our master private key

    val m_pub = publicKey(m)
    assert(encode(m_pub, xpub) === "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert(fingerprint(m) === 876747070)

    val m42 = derivePrivateKey(m, 42L)

    // now we have: the master public key, and a child private key, and we want to climb the tree back up
    // to the parent private key
    val I = Crypto.hmac512(m_pub.chaincode, m_pub.publickeybytes ++ writeUInt32(42, ByteOrder.BIG_ENDIAN))
    val IL = I.take(32)
    val guess = new BigInteger(1, m42.secretkeybytes.toArray).subtract(new BigInteger(1, IL.toArray)).mod(Crypto.curve.getN)
    assert(guess === k)
  }

  it should "parse string-formatted derivation paths" in {
    assert(KeyPath("m/44'/0'/0'/0") == KeyPath(hardened(44) :: hardened(0) :: hardened(0) :: 0L :: Nil))
    assert(KeyPath("/44'/0'/0'/0") == KeyPath(hardened(44) :: hardened(0) :: hardened(0) :: 0L :: Nil))
    assert(KeyPath("44'/0'/0'/0") == KeyPath(hardened(44) :: hardened(0) :: hardened(0) :: 0L :: Nil))
    assert(KeyPath("m/44/0'/0'/0") == KeyPath(44L :: hardened(0) :: hardened(0) :: 0L :: Nil))
    assert(KeyPath("m") == KeyPath.Root)
    assert(KeyPath("") == KeyPath.Root)
    val invalidKeyPaths = Seq(
      "aa/1/2/3", "1/'2/3"
    )
    invalidKeyPaths.map(path => {
      intercept[RuntimeException] {
        println(KeyPath(path))
      }
    })
  }

  it should "be able to derive private keys" in {
    val random = new Random()
    val seed = new Array[Byte](32)
    for (_ <- 0 until 50) {
      random.nextBytes(seed)
      val master = DeterministicWallet.generate(ByteVector.view(seed))
      for (_ <- 0 until 50) {
        val index = random.nextLong()
        val priv = DeterministicWallet.derivePrivateKey(master, index)

        val encoded = DeterministicWallet.encode(priv, DeterministicWallet.tprv)
        val (prefix, decoded) = DeterministicWallet.ExtendedPrivateKey.decode(encoded)
        assert(prefix == DeterministicWallet.tprv)
        assert(decoded.chaincode == priv.chaincode && decoded.secretkeybytes == priv.secretkeybytes)

        val pub = DeterministicWallet.publicKey(priv)
        val encoded1 = DeterministicWallet.encode(pub, DeterministicWallet.tpub)
        val (prefix1, decoded1) = DeterministicWallet.ExtendedPublicKey.decode(encoded1)
        assert(prefix1 == DeterministicWallet.tpub)
        assert(decoded1.chaincode == pub.chaincode && decoded1.publicKey == pub.publicKey)
      }
    }
  }
}
