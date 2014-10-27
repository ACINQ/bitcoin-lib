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

## Limitations and compatibility issues

This is a very early beta release and should not be used in production. If you're looking for a mature bitcoin library for the JVM you should
have a look at [bitcoinj](https://github.com/bitcoinj/bitcoinj) instead.

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
    <version>0.9.2</version>
  </dependency>
</dependencies>
```

The latest snapshot (development) version is 0.9.3-SNAPSHOT, the latest released version is 0.9.2

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

