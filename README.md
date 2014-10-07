# Simple Scala Bitcoin Library

Simple bitcoin library written in Scala.

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
have a look at bitcoinj instead.

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


