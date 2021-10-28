package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.Crypto.PublicKey
import fr.acinq.bitcoinscala.DeterministicWallet.KeyPath
import org.scalatest.FunSuite
import scodec.bits._

/**
  * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
  * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  */
class BIP84Spec extends FunSuite {
  test("BIP84 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.zprv) == "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub) == "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv) == "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub) == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/0/0")).secretkeybytes)
    assert(key.privateKey.toBase58(Base58.Prefix.SecretKey) == "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
    assert(key.publicKey == PublicKey(hex"0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"))
    assert(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    val key1 = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 1L :: Nil)
    assert(key1.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/0/1")).secretkeybytes)
    assert(key1.privateKey.toBase58(Base58.Prefix.SecretKey) == "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy")
    assert(key1.publicKey == PublicKey(hex"03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"))
    assert(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash) == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")

    val key2 = DeterministicWallet.derivePrivateKey(accountKey, 1L :: 0L :: Nil)
    assert(key2.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/1/0")).secretkeybytes)
    assert(key2.privateKey.toBase58(Base58.Prefix.SecretKey) == "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF")
    assert(key2.publicKey == PublicKey(hex"03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6"))
    assert(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash) == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
  }
}
