# Simple Scala Bitcoin Library

Simple bitcoin library written in Scala.

[![Build Status](https://travis-ci.org/ACINQ/bitcoin-lib.png)](https://travis-ci.org/ACINQ/bitcoin-lib)

## Overview

This is a simple scala library which implements some (most ?) of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx signature and verification
* script parsing and execution
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 70

## Objectives

Our goal is not to re-implement a full Bitcoin node (this would be a doomed and rather pointless endeavour) but to build a library that can be used to build applications that rely on bitcoind to interface with the Bitcoin network (to retrieve and index transactions and blocks, for example...). We also use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocole are fairly simple and "safe" to re-implement (BIP32 for example).  
This is a very early beta release and should not be used in production. If you're looking for a mature bitcoin library for the JVM you should have a look at [bitcoinj](https://github.com/bitcoinj/bitcoinj) instead.

Not all script instructions have been implemented, but as is the library should be able to parse and validate the entire blockchain.

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
    <version>0.9.3</version>
  </dependency>
</dependencies>
```

The latest snapshot (development) version is 0.9.4-SNAPSHOT, the latest released version is 0.9.3

## Usage

Please have a look at unit tests, more samples will be added soon.

### Pay to Public Key

```scala
  // simple pay to PK tx

  // we own a public/key private key pair
  val (_, publicKeyHash) = Address.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")
  val (_, privateKey) = Address.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")

  // we want to redeem the output of a previous transaction that was sent to mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY. The id of this tx is
  // dd2218b50eb64b0d1d0d2d4c31c1a9308966e22ebebe0ffae7035b592e39bc14
  val previousTxPubKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(publicKeyHash) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
  // this is our input:
  val txIn = TxIn(
    OutPoint(hash = fromHexString("dd2218b50eb64b0d1d0d2d4c31c1a9308966e22ebebe0ffae7035b592e39bc14").reverse, 0),
    signatureScript = previousTxPubKeyScript,
    sequence = 0xFFFFFFFFL
  )

  // we want to send 10 BTC from the previous tx output to mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3
  val destinationAddress = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
  val amount = 10
  // this is our output:
  val txOut = TxOut(
    amount = amount,
    publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(destinationAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
  )

  // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
  val tx1 = Transaction(
    version = 1L,
    txIn = List(txIn),
    txOut = List(txOut),
    lockTime = 0L
  )

  // step #2: sign the tx
  val tx2 = Transaction.sign(tx1, List(SignData(previousTxPubKeyScript, privateKey)))

  // this is what we would send over the BTC network
  println(s"raw tx: ${toHexString(Transaction.write(tx2))}")

  // and a more readable JSON version
  println(s"json tx: ${Json.toJson(tx2, testnet = true)}")
```

### Pay to Script: multisig transactions

```scala

  val pub1 = fromHexString("0394D30868076AB1EA7736ED3BDBEC99497A6AD30B25AFD709CDF3804CD389996A")
  val key1 = fromHexString("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA")
  val pub2 = fromHexString("032C58BC9615A6FF24E9132CEF33F1EF373D97DC6DA7933755BC8BB86DBEE9F55C")
  val key2 = fromHexString("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C")
  val pub3 = fromHexString("02C4D72D99CA5AD12C17C9CFE043DC4E777075E8835AF96F46D8E3CCD929FE1926")
  val key3 = fromHexString("29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C")

  // create a "2 out of 3" multisig script
  val redeemScript = Script.createMultiSigMofN(2, List(pub1, pub2, pub3))

  // the multisig adress is just that hash of this script
  val multisigAddress = Crypto.hash160(redeemScript)

  // we want to send money to our multisig adress by redeeming the first output
  // of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
  // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
  val txIn = TxIn(
    OutPoint(fromHexString("41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea").reverse, 0),
    signatureScript = Array(), // empy signature script
    sequence = 0xFFFFFFFFL)

  // and we want to sent the output to our multisig address
  val txOut = TxOut(
    amount = 900000, // 0.009 BTC in satoshi, meaning the fee will be 0.01-0.009 = 0.001
    publicKeyScript = Script.write(OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil))

  // create a tx with empty input signature scripts
  val tx = Transaction(version = 1L, txIn = List(txIn), txOut = List(txOut), lockTime = 0L)

  // and sign it
  val signData = SignData(
    fromHexString("76a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac"), // PK script of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
    Address.decode("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM")._2)

  val signedTx = Transaction.sign(tx, List(signData))

```
### HD Wallet

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
