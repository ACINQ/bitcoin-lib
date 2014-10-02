package fr.acinq.bitcoin

import java.math.BigInteger

import org.junit.runner.RunWith
import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class DeterministicWalletSpec extends FlatSpec {
  import fr.acinq.bitcoin.DeterministicWallet._

  // these tests are the "official" ones (see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

  "Determinstic Wallet" should "generate and derive keys (test vector #1)" in {
    val m = generate(fromHexString("000102030405060708090a0b0c0d0e0f"))
    assert(encode(m, testnet = false) === "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

    val m_pub = publicKey(m)
    assert(encode(m_pub, testnet = false) === "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert(fingerprint(m) === 876747070)

    val m0h = derivePrivateKey(m, 0x80000000L)
    assert(encode(m0h, testnet = false) === "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    val m0h_pub = publicKey(m0h)
    assert(encode(m0h_pub, testnet = false) === "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

    val m0h_1 = derivePrivateKey(m0h, 1L)
    assert(encode(m0h_1, testnet = false) === "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
    val m0h_1_pub = publicKey(m0h_1)
    assert(encode(m0h_1_pub, testnet = false) === "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

    // check that we can also derive this public key from the parent's public key
    val m0h_1_pub1 = derivePublicKey(m0h_pub, 1L)
    assert(encode(m0h_1_pub1, testnet = false) === "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

    val m0h_1_2h = derivePrivateKey(m0h_1, 2 + 0x80000000L)
    assert(encode(m0h_1_2h, testnet = false) === "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
    val m0h_1_2h_pub = publicKey(m0h_1_2h)
    assert(encode(m0h_1_2h_pub, testnet = false) === "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")
    intercept[IllegalArgumentException] {
      derivePublicKey(m0h_1_pub, 2 + 0x80000000L)
    }

    val m0h_1_2h_2 = derivePrivateKey(m0h_1_2h, 2)
    assert(encode(m0h_1_2h_2, testnet = false) === "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
    val m0h_1_2h_2_pub = publicKey(m0h_1_2h_2)
    assert(encode(m0h_1_2h_2_pub, testnet = false) === "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
    val m0h_1_2h_2_pub1 = derivePublicKey(m0h_1_2h_pub, 2)
    assert(encode(m0h_1_2h_2_pub1, testnet = false) === "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

    val m0h_1_2h_2_1000000000 = derivePrivateKey(m0h_1_2h_2, 1000000000L)
    assert(encode(m0h_1_2h_2_1000000000, testnet = false) === "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
    val m0h_1_2h_2_1000000000_pub = publicKey(m0h_1_2h_2_1000000000)
    assert(encode(m0h_1_2h_2_1000000000_pub, testnet = false) === "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

    assert(encode(derivePrivateKey(m, 0x80000000L :: 1L :: (2 + 0x80000000L) :: 2L :: 1000000000L :: Nil), testnet = false) === "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
  }
  it should "generate and derive keys (test vector #2)" in {
    val m = generate(fromHexString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
    assert(encode(m, testnet = false) === "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")

    val m_pub = publicKey(m)
    assert(encode(m_pub, testnet = false) === "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

    val m0 = derivePrivateKey(m, 0L)
    assert(encode(m0, testnet = false) === "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
    val m0_pub = publicKey(m0)
    assert(encode(m0_pub, testnet = false) === "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

    val m0_2147483647h = derivePrivateKey(m0, 2147483647 + 0x80000000L)
    assert(encode(m0_2147483647h, testnet = false) === "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
    val m0_2147483647h_pub = publicKey(m0_2147483647h)
    assert(encode(m0_2147483647h_pub, testnet = false) === "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

    val m0_2147483647h_1 = derivePrivateKey(m0_2147483647h, 1)
    assert(encode(m0_2147483647h_1, testnet = false) === "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
    val m0_2147483647h_1_pub = publicKey(m0_2147483647h_1)
    assert(encode(m0_2147483647h_1_pub, testnet = false) === "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

    val m0_2147483647h_1_2147483646h = derivePrivateKey(m0_2147483647h_1, 2147483646 + 0x80000000L)
    assert(encode(m0_2147483647h_1_2147483646h, testnet = false) === "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
    val m0_2147483647h_1_2147483646h_pub = publicKey(m0_2147483647h_1_2147483646h)
    assert(encode(m0_2147483647h_1_2147483646h_pub, testnet = false) === "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

    val m0_2147483647h_1_2147483646h_2 = derivePrivateKey(m0_2147483647h_1_2147483646h, 2)
    assert(encode(m0_2147483647h_1_2147483646h_2, testnet = false) === "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
    val m0_2147483647h_1_2147483646h_2_pub = publicKey(m0_2147483647h_1_2147483646h_2)
    assert(encode(m0_2147483647h_1_2147483646h_2_pub, testnet = false) === "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")
  }
  it should "be possible to go up the private key chain if you have the master pub key and a child private key!!" in {
    val m = generate(fromHexString("000102030405060708090a0b0c0d0e0f"))
    assert(encode(m, testnet = false) === "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    val k = new BigInteger(1, m.secretkey) // k is our master private key

    val m_pub = publicKey(m)
    assert(encode(m_pub, testnet = false) === "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert(fingerprint(m) === 876747070)

    val m42 = derivePrivateKey(m, 42L)

    // now we have: the master public key, and a child private key, and we want to climb the tree back up
    // to the parent private key
    val I = hmac512(m_pub.chaincode, m_pub.publickey ++ writeUInt32BigEndian(42L))
    val IL = I.take(32)
    val IR = I.takeRight(32)
    val guess = new BigInteger(1, m42.secretkey).subtract(new BigInteger(1, IL)).mod(Crypto.curve.getN)
    assert(guess === k)
  }
}
