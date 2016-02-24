# Simple Scala Bitcoin Library

Simple bitcoin library written in Scala.

[![Build Status](https://travis-ci.org/ACINQ/bitcoin-lib.png)](https://travis-ci.org/ACINQ/bitcoin-lib)

## Overview

This is a simple scala library which implements most of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx signature and verification
* script parsing and execution (including OP_CLTV and OP_CSV)
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 70

## Objectives

Our goal is not to re-implement a full Bitcoin node but to build a library that can be used to build applications that rely on bitcoind to interface with the Bitcoin network (to retrieve and index transactions and blocks, for example...). We also use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocole are fairly simple and "safe" to re-implement (BIP32/BIP39 for example).  
This is a very early beta release and should not be used in production. If you're looking for a mature bitcoin library for the JVM you should have a look at [bitcoinj](https://github.com/bitcoinj/bitcoinj) instead.

## Configuring maven/sbt

* releases and milestones are pushed to maven central
* snapshots are pushed to the sonatype snapshot repository

```xml
 <repositories>
    <repository>
        <id>sonatype snapshots</id>
        <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
    </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>fr.acinq</groupId>
    <artifactId>bitcoin-lib_2.11</artifactId>
    <version>0.9.5</version>
  </dependency>
</dependencies>
```

The latest snapshot (development) version is 0.9.6-SNAPSHOT, the latest released version is 0.9.5

## Usage

Please have a look at unit tests, more samples will be added soon.

### Public keys, private keys, addresses

```shell

mvn scala:console
scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> val priv:BinaryData = "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"
priv: fr.acinq.bitcoin.BinaryData = 1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd

scala> val pubUncompressed:BinaryData = Crypto.publicKeyFromPrivateKey(priv)
pubUncompressed: fr.acinq.bitcoin.BinaryData = 04f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb

scala> val pubCompressed:BinaryData = Crypto.publicKeyFromPrivateKey(priv :+ 1.toByte)
pubCompressed: fr.acinq.bitcoin.BinaryData = 03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(pubUncompressed))
res0: String = 1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(pubCompressed))
res1: String = 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy

scala> Base58Check.encode(Base58.Prefix.SecretKey, priv)
res2: String = 5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn

scala> Base58Check.encode(Base58.Prefix.SecretKey, priv :+ 1.toByte)
res3: String = KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ

```

### Pay to Public Key

```scala
  // simple pay to PK tx

  // we have a tx that was sent to a public key that we own
  val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")
  val (Base58.Prefix.SecretKeyTestnet, privateKey) = Base58Check.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")

  // we want to send money from the previous tx output to mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3
  val destinationAddress = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"

  // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
  val unsignedTx = Transaction(
    version = 1L,
    txIn =  TxIn(OutPoint(previousTx.hash, 0), signatureScript = Array.emptyByteArray, sequence = 0xFFFFFFFFL) :: Nil,
    txOut = TxOut(amount = 10000, OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(destinationAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
    lockTime = 0L)

  // step #2: sign it
  val signedTx = Transaction.sign(unsignedTx, SignData(previousTx.txOut(0).publicKeyScript, privateKey) :: Nil)

  // check that it actually spends the previous tx
  Transaction.correctlySpends(signedTx, previousTx :: Nil, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
```

### Pay to Script: multisig transactions

```scala

  val pub1: BinaryData = "0394D30868076AB1EA7736ED3BDBEC99497A6AD30B25AFD709CDF3804CD389996A"
  val key1: BinaryData = "C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA"
  val pub2: BinaryData = "032C58BC9615A6FF24E9132CEF33F1EF373D97DC6DA7933755BC8BB86DBEE9F55C"
  val key2: BinaryData = "5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C"
  val pub3: BinaryData = "02C4D72D99CA5AD12C17C9CFE043DC4E777075E8835AF96F46D8E3CCD929FE1926"
  val key3: BinaryData = "29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C"

  // we want to spend the first output of this tx
  val previousTx = Transaction.read("01000000014100d6a4d20ff14dfffd772aa3610881d66332ed160fc1094a338490513b0cf800000000fc0047304402201182201b586c6bfe6fd0346382900834149674d3cbb4081c304965440b1c0af20220023b62a997f4385e9279dc1078590556c6c6a85c3ec20fda407e95eb270e4de90147304402200c75f91f8bd741a8e71d11ff6a3e931838e32ceead34ccccfe3f73f01a81e45f02201795881473644b5f5ee6a8d8a90fe16e60eacace40e88900c375af2e0c51e26d014c69522103bd95bfc136869e2e5e3b0491e45c32634b0201a03903e210b01be248e04df8702103e04f714a4010ca5bb1423ef97012cb1008fb0dfd2f02acbcd3650771c46e4a8f2102913bd21425454688bdc2df2f0e518c5f3109b1c1be56e6e783a41c394c95dc0953aeffffffff0140420f00000000001976a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac00000000")
  val (Base58.Prefix.SecretKeyTestnet, privateKey) = Base58Check.decode("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM")
  val publicKey = Crypto.publicKeyFromPrivateKey(privateKey)

  // create a "2 out of 3" multisig script
  val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))

  // the multisig adress is just that hash of this script
  val multisigAddress = Crypto.hash160(redeemScript)

  // we want to send money to our multisig adress by redeeming the first output
  // of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
  // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM

  // create a tx with empty input signature scripts
  val tx = Transaction(version = 1L,
    txIn = TxIn(OutPoint(previousTx.hash, 0), signatureScript = Array.emptyByteArray, sequence = 0xFFFFFFFFL) :: Nil,
    txOut = TxOut(
      amount = 900000, // 0.009 BTC in satoshi, meaning the fee will be 0.01-0.009 = 0.001
      publicKeyScript = OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil) :: Nil,
    lockTime = 0L)

  // and sign it
  val signData = SignData(
    fromHexString("76a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac"), // PK script of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
    Base58Check.decode("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM")._2)

  val signedTx = Transaction.sign(tx, Seq(SignData(previousTx.txOut(0).publicKeyScript, privateKey)))
  Transaction.correctlySpends(signedTx, previousTx :: Nil, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)


  // how to spend our tx ? let's try to sent its output to our public key
  val spendingTx = Transaction(version = 1L,
    txIn = TxIn(OutPoint(signedTx.hash, 0), signatureScript = Array.emptyByteArray, sequence = 0xFFFFFFFFL) :: Nil,
    txOut = TxOut(
      amount = 900000,
      publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(publicKey)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
    lockTime = 0L)

  // we need at least 2 signatures
  val sig1 = Transaction.signInput(spendingTx, 0, redeemScript, SIGHASH_ALL, key1)
  val sig2 = Transaction.signInput(spendingTx, 0, redeemScript, SIGHASH_ALL, key2)

  // update our tx with the correct sig script
  val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
  val signedSpendingTx = spendingTx.updateSigScript(0, Script.write(sigScript))
  Transaction.correctlySpends(signedSpendingTx, signedTx :: Nil, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

```
### HD Wallet (BIP32)

Let's play with the scala console and the first test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

```shell
mvn scala:console
[INFO] Scanning for projects...
[INFO]
[INFO] ------------------------------------------------------------------------
[INFO] Building bitcoin-lib 0.9.4-SNAPSHOT
[INFO] ------------------------------------------------------------------------
[INFO]
[INFO] --- scala-maven-plugin:3.2.0:console (default-cli) @ bitcoin-lib_2.11 ---
[WARNING]  Expected all dependencies to require Scala version: 2.11.4
[WARNING]  fr.acinq:bitcoin-lib_2.11:0.9.4-SNAPSHOT requires scala version: 2.11.4
[WARNING]  com.github.scopt:scopt_2.11:3.2.0 requires scala version: 2.11.0
[WARNING] Multiple versions of scala libraries detected!
[WARNING] scala-maven-plugin cannot fork scala console!!  Running in process
Welcome to Scala version 2.11.1 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_31).
Type in expressions to have them evaluated.
Type :help for more information.

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import fr.acinq.bitcoin.DeterministicWallet
DeterministicWallet   DeterministicWalletSpec

scala> import fr.acinq.bitcoin.DeterministicWallet._
import fr.acinq.bitcoin.DeterministicWallet._

scala> val m = generate(fromHexString("000102030405060708090a0b0c0d0e0f"))
m: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(m, false)
res1: String = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

scala> publicKey(m)
res2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(publicKey(m), false)
res3: String = xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

scala> val priv = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: 2L :: Nil)
priv: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4,cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd,4,m/0h/1/2h/2,4001020172)

scala> encode(priv, false)
res5: String = xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334

scala> encode(publicKey(priv), false)
res6: String = xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV

scala> val k2 = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: Nil)
k2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(cbce0d719ecf7431d88e6a89fa1483e02e35092
af60c042b1df2ff59fa424dca,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0h/1/2h,3203769081)

scala> val K2 = publicKey(k2)
K2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0357bfe1e341d01c69fe5654309956cbea516822f
ba8a601743a012a7896ee8dc2,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0h/1/2h,3203769081)

scala> derivePublicKey(K2, 2L :: 1000000000L :: Nil)
res8: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011,c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e,5,m/0h/1/2h/2/1000000000,3632322520)

scala> encode(derivePublicKey(K2, 2L :: 1000000000L :: Nil), false)
res10: String = xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy

```

### Mnemonic code (BIP39)

```shell
mvn scala:console
[INFO] Scanning for projects...
[INFO]
[INFO] ------------------------------------------------------------------------
[INFO] Building bitcoin-lib 0.9.4-SNAPSHOT
[INFO] ------------------------------------------------------------------------
[INFO]
[INFO] --- scala-maven-plugin:3.2.0:console (default-cli) @ bitcoin-lib_2.11 ---
[WARNING]  Expected all dependencies to require Scala version: 2.11.6
[WARNING]  fr.acinq:bitcoin-lib_2.11:0.9.4-SNAPSHOT requires scala version: 2.11.6
[WARNING]  org.json4s:json4s-jackson_2.11:3.2.11 requires scala version: 2.11.0
[WARNING] Multiple versions of scala libraries detected!
[WARNING] scala-maven-plugin cannot fork scala console!!  Running in process
Welcome to Scala version 2.11.6 (Java HotSpot(TM) 64-Bit Server VM, Java 1.8.0_45).
Type in expressions to have them evaluated.
Type :help for more information.

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import MnemonicCode._
import MnemonicCode._

scala> val mnemonics = toMnemonics(fromHexString("77c2b00716cec7213839159e404db50d"))
mnemonics: List[String] = List(jelly, better, achieve, collect, unaware, mountain, thought, cargo, oxygen, act, hood, bridge)

scala> val key:BinaryData = toSeed(mnemonics, "TREZOR")
key: fr.acinq.bitcoin.BinaryData = b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43
897fc4e51a6ff
```
