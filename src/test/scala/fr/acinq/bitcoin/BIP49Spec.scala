package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import org.scalatest.FunSuite
import scodec.bits._

/**
  * BIP 49 (Derivation scheme for P2WPKH-nested-in-P2SH based accounts) reference tests
  * see https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
  */
class BIP49Spec extends FunSuite {
  test("BIP49 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.tprv) == "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.tprv) == "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'/0/0")).secretkeybytes)
    assert(key.privateKey.toBase58(Base58.Prefix.SecretKeyTestnet) == "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ")
    assert(key.privateKey == PrivateKey(hex"0xc9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e801"))
    assert(key.publicKey == PublicKey(hex"0x03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"))
    assert(computeBIP49Address(key.publicKey, Block.TestnetGenesisBlock.hash) == "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")
  }
}
