# Simple Scala Bitcoin Library

[![Build Status](https://github.com/ACINQ/bitcoin-lib/workflows/Build%20&%20Test/badge.svg)](https://github.com/ACINQ/bitcoin-lib/actions?query=workflow%3A%22Build+%26+Test%22)
[![Maven Central](https://img.shields.io/maven-central/v/fr.acinq/bitcoin-lib_2.13)](https://search.maven.org/search?q=g:fr.acinq%20a:bitcoin-lib_2.13*)[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Overview

This is a simple scala library which implements most of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx creation, signature and verification
* script parsing and execution (including OP_CLTV and OP_CSV)
* standard scripts (p2pkh, p2sh, p2wpkh, p2wsh)
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 173 (Base32 address format for native v0-16 witness outputs)
* BIP 174 (Partially Signed Bitcoin Transaction Format)
* BIP 350 (Bech32m format)

It is actually a wrapper on top of our [Kotlin Bitcoin Library](https://github.com/ACINQ/bitcoin-kmp) that makes it easier to use in scala projects.
All the features are implemented in Kotlin in the `fr.acinq.bitcoin` namespace and the scala wrappers can be found in the `fr.acinq.bitcoin.scalacompat` namespace.

## Objectives

Our goal is not to re-implement a full Bitcoin node but to build a library that can be used to build applications that rely on bitcoind to interface with the Bitcoin network (to retrieve and index transactions and blocks, for example...). We use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocol are fairly simple and "safe" to re-implement (BIP32/BIP39 for example), especially for indexing/analysis purposes. And, of course, we use it for our own work on Lightning (see <https://github.com/ACINQ/eclair>).

## Status

* [X] Message parsing (blocks, transactions, ...)
* [X] Building transactions (P2PK, P2PKH, P2SH, P2WPKH, P2WSH)
* [X] Signing transactions
* [X] Verifying signatures
* [X] Passing core reference tests (scripts & transactions)
* [X] Passing core reference segwit tests
* [X] Passing core reference psbt tests

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
    <artifactId>bitcoin-lib_2.13</artifactId>
    <version>0.27</version>
  </dependency>
</dependencies>
```

The latest snapshot (development) version is 0.28-SNAPSHOT, the latest released version is 0.27.

## libsecp256k1 support

Bitcoin-lib embeds JNI bindings for libsecp256k1 through [secp256k1-kmp](https://github.com/ACINQ/secp256k1-kmp/).
It will extract and load native bindings for your operating system in a temporary directory.

JNI libraries are included for:

* Linux 64 bits
* Windows 64 bits
* Osx 64 bits

Please have a look at the [secp256k1-kmp documentation](https://github.com/ACINQ/secp256k1-kmp/) for advanced scenarios.

## Usage

Please have a look at unit tests of this library and of [bitcoin-kmp](https://github.com/ACINQ/bitcoin-kmp), they will contain the most up-to-date samples.

### Basic type: public keys, private keys, addresses

We defined only a limited set of specific types (private keys, public keys). There is a simple BinaryData type
that can be used to convert to/from Array[Byte], Seq[Byte], and hexadecimal Strings.

As much as possible, the library uses and produces raw binary data, without fancy wrapper types and encoding. This should
make importing/exporting data from/to other libraries easy. It also makes it easy to use binary data used in examples, books,
or produced by debugging tools.

The following REPL session shows how to create and use keys and addresses:

```shell
mvn scala:console
scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import fr.acinq.bitcoin.scalacompat.Crypto._
import fr.acinq.bitcoin.scalacompat.Crypto._

scala> import scodec.bits._
import scodec.bits._

scala> val priv = PrivateKey(hex"1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")
priv: fr.acinq.bitcoin.Crypto.PrivateKey = PrivateKey(1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd)

scala> val pub = priv.publicKey
pub: fr.acinq.bitcoin.Crypto.PublicKey = PublicKey(03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a)

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160)
res0: String = 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy

scala> priv.toBase58(Base58.Prefix.SecretKey)
res2: String = KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ
```

### Building and verifying transactions

The Transaction class can be used to create, serialize, deserialize, sign and validate bitcoin transactions.

#### P2PKH transactions

A P2PKH transactions sends bitcoins to a public key hash, using a standard P2PKH script:

``` scala
val pkh = pubKey.hash160
val pubKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pkh) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil
```

To spend it, just provide a signature and the public key:

```scala
val sigScript = OP_PUSHDATA(sig) :: OP_PUSHDATA(pubKey.toBin) :: Nil
```

This sample demonstrates how to serialize, create and verify simple P2PKH transactions.

```scala
    // simple pay to PK tx

    // we have a tx that was sent to a public key that we own
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val (Base58.Prefix.PubkeyAddressTestnet, pubkeyHash) = Base58Check.decode(to)
    val amount = 10000 sat

    val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val publicKey = privateKey.publicKey

    val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")

    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(OutPoint(previousTx, 0), signatureScript = Nil, sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(amount = amount, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pubkeyHash) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      ),
      lockTime = 0L
    )

    // step #2: sign the tx
    val sig = Transaction.signInput(tx1, 0, previousTx.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, privateKey)
    val tx2 = tx1.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)

    // redeem the tx
    Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
```

#### P2SH transactions

A P2SH transactions sends bitcoins to a script hash:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val multisigAddress = Crypto.hash160(redeemScript)
val publicKeyScript = OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil
```

To spend it, you must provide data that will match the public key script, and the actual public key script. In our case,
we need 2 valid signatures:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
```

This sample demonstrates how to serialize, create and verify a multisig P2SH transaction

```scala
    val priv1 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

    assert(address1 == "mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA")

    val priv2 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.05 BTC to mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA
    val tx1 = Transaction.read("020000000001016ecc08b535a0c774234419dee508867ace1535a0d256d6b2aa19942441777336000000002322002073bb471aa121fbdd95942eabb5e665d66e71542e6e075c8392cd0df72a075b72fdffffff02803823030000000017a914d3c15be7951c9de644bdf9e22dcbcb77550c4ae487404b4c00000000001976a9143545b2a6659dbe5bdf841d1158135be184d81d3688ac0400473044022041cac92405e4e3215c2f9c27a67ff0792c8fb76e4182023fed081f541f4563e002203bd04d4d810ef8074aeb26a19e01e1ee1a40ad83e4d0ac2c614b8cb22825d2ae0147304402204c947b46ea480419c04098a56a5219bb1f491b07e12926fb6f304132a1f1e29e022078cc9f004c74d6c3c2b2dfcca6385d2fabe44d4eadb027a0d764e1ab9d7f09190147522102be608bf8904326b4d0ec9346aa348773fe51ee70338849acd2dd710b73bf611a2103627c19e40f67c5ee8b44df85ee911b7e978869fa5a3de1d972a461f47ea349e452ae90bb2300", pversion)

    // now let's create a simple tx that spends tx1 and send 0.049 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.049 btc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      //Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9"))
    // this tx was published on testnet as 2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9

    // and now we create a testnet tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.048 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a"))
    // this tx was published on testnet as 4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a
```

#### P2WPKH transactions

This is the simplest segwit transaction, equivalent to standard P2PKH transactions but more compact:

```scala
val pkh = pubKey.hash160
val pubKeyScript = OP_0 :: OP_PUSHDATA(pkh) :: Nil
```

To spend them, you provide a witness that is just a push of a signature and the actual public key:

```scala
val witness = ScriptWitness(sig :: pubKey :: Nil))
```

This sample demonstrates how to serialize, create and verify a P2WPKH transaction

```scala
    val priv1 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

    assert(address1 == "mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA")

    // this is a standard tx that sends 0.04 BTC to mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA
    val tx1 = Transaction.read("02000000000101516508384a3e006340f1ea700eb3635330beed5d94c7b460b6b495eb1593d55c0100000023220020a5fdf5b5f2c592362b78a50997821964b39dd90476c6e1f3e97e79acb134ca3bfdffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388aca005071d0000000017a914d77e5f7ca4d9f05dc4f25dc0aa1391f0e901bdfc87040047304402207bfb18327be173512f38bd4120b8f02545321ecc6105a852cbc25b1de687ba570220705a1225d8a8e0fbd4b35f3bc38a2840706f8524e8dc6f0151746aeff14033ce014730440220486925fb0495442e4ccb1b711692af7057d4db24f8775b5dfa3f8c74992081f102203beae7d96423e0c66b7b5f8919a5f3ad89a42dc4303f37201e4e596909478357014752210245119449d07c16992c148e3b33f1395ee05c936fc510d9fae83417f8e1901f922103eb03f67b56c88bccff90b76182c08556eac9ebc5a0efee8669bef69ae6d4ea5752ae75bb2300", pversion)

    // now let's create a simple tx that spends tx1 and send 0.039 BTC to P2WPKH output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.39 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3"))
    // this tx was published on testnet as f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3

    // and now we create a segwit tx that spends the P2WPKH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.038 btc, Script.pay2wpkh(pub1)) :: Nil, // we reuse the same output script but if could be anything else
        lockTime = 0
      )
      // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
      // of the pubkey hash), but the actual script that is evaluated by the script engine, in this case a PAY2PKH script
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa"))
    // this tx was published on testnet as 739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa
```

#### P2WSH transactions

P2WSH transactions are the segwit version of P2SH transactions:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val pubKeyScript = OP_0 :: OP_PUSHDATA(Crypto.sha256(redeemScript)) :: Nil) :: Nil,
```

To spend them, you provide data that wil match the publick key script, and the actual public key script:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, redeemScript))
```

This sample demonstrates how to serialize, create and verify a P2WSH transaction

```scala
    val priv1 = PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value))

    assert(address1 == "mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ")

    val priv2 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.05 BTC to mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ
    val tx1 = Transaction.read("020000000001016ecc08b535a0c774234419dee508867ace1535a0d256d6b2aa19942441777336000000002322002073bb471aa121fbdd95942eabb5e665d66e71542e6e075c8392cd0df72a075b72fdffffff02803823030000000017a914d3c15be7951c9de644bdf9e22dcbcb77550c4ae487404b4c00000000001976a9143545b2a6659dbe5bdf841d1158135be184d81d3688ac0400473044022041cac92405e4e3215c2f9c27a67ff0792c8fb76e4182023fed081f541f4563e002203bd04d4d810ef8074aeb26a19e01e1ee1a40ad83e4d0ac2c614b8cb22825d2ae0147304402204c947b46ea480419c04098a56a5219bb1f491b07e12926fb6f304132a1f1e29e022078cc9f004c74d6c3c2b2dfcca6385d2fabe44d4eadb027a0d764e1ab9d7f09190147522102be608bf8904326b4d0ec9346aa348773fe51ee70338849acd2dd710b73bf611a2103627c19e40f67c5ee8b44df85ee911b7e978869fa5a3de1d972a461f47ea349e452ae90bb2300", pversion)

    // now let's create a simple tx that spends tx1 and sends 0.049 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.049 btc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      //Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9"))
    // this tx was published on testnet as 2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.048 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a"))
    // this tx was published on testnet as 4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a
```

#### Segwit transactions embedded in standard P2SH transactions

```scala
    val priv1 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey

    // p2wpkh script
    val script = Script.write(Script.pay2wpkh(pub1))

    // which we embeed into a standard p2sh script
    val p2shaddress = Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script))
    assert(p2shaddress === "2NB3GUVxBF3P7NLMkSGNai33mWkM35ht1Xj")

    // this tx send 0.5 btc to our p2shaddress
    val tx = Transaction.read("02000000000101d9ee0034f9ae4fac7a4017d78e26e1c492d507e16f3535ecbc2ea72cb1c4c6f501000000232200208a15b02dab825f2a4b60b58a7c8591c659a3eb18765fd9d926332c0cea574e2ffdffffff02d292e4000000000017a914aefbc2c20e0c312a616cf7c4ebbacc5c9a04432787404b4c000000000017a914c32f5922344dbe1abd4fb1744b560b5d1875353987040047304402205fbba2ab917efc23209fe04086fb5f714e527d088e2a5ec19590ec4b566a8c2d02206607f3e42eaff5d30dd6297dcb4d48300a75819a358c0bc20396e393ab1594260147304402206a0df35cb8fc58fb21b111d432abc7f9f74836ad1e35c63be2f0c772d4a2ce49022076c4c96a7a9d18577a5e762a3dc3e4b728fd950284c133eb3147707b9181f90b01475221039c40944fe4f90f46760621a1ca66d3141f7e81ccccfa2cf4550fdb9b432c52ed2102976af59e7b61fb3c7a6a2553d7b030a5e292fdda6eba439b4a24af494b3475c752aebebb2300", pversion)

    // let's spend it:

    val tx1 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx.hash, 1), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.049 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1.value)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx.txOut(1).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateSigScript(0, OP_PUSHDATA(script) :: Nil).updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx1.txid === ByteVector32(hex"4807cb10f50df84acd7766245133f902d22d91b7e8bfe77c4bbcb0cf9b017a86"))
    // this tx was published on testnet as 4807cb10f50df84acd7766245133f902d22d91b7e8bfe77c4bbcb0cf9b017a86
```

### Wallet features

Bitcoin-lib provides and simple and complete implementation of BIP32 and BIP39.

#### HD Wallet (BIP32)

Let's play with the scala console and the first test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

```shell
mvn scala:console

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import scodec.bits._
import scodec.bits._

scala> import fr.acinq.bitcoin.DeterministicWallet
DeterministicWallet   DeterministicWalletSpec

scala> import fr.acinq.bitcoin.DeterministicWallet._
import fr.acinq.bitcoin.DeterministicWallet._

scala> val m = generate(hex"000102030405060708090a0b0c0d0e0f")
m: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(m, xprv)
res1: String = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

scala> publicKey(m)
res2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(publicKey(m), xpub)
res3: String = xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

scala> val priv = derivePrivateKey(m, KeyPath("0'/1/2'/2"))
priv: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4,cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd,4,m/0h/1/2h/2,4001020172)

scala> encode(priv, xprv)
res5: String = xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334

scala> encode(publicKey(priv), xpub)
res6: String = xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV

scala> val k2 = derivePrivateKey(m, KeyPath("0'/1/2'"))
k2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> val K2 = publicKey(k2)
K2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(ByteVector(33 bytes, 0x0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2),04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> derivePublicKey(K2, KeyPath("2/1000000000"))
res6: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(ByteVector(33 bytes, 0x022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011),c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e,5,m/0'/1/2'/2/1000000000,3632322520)

scala> encode(derivePublicKey(K2, KeyPath("2/1000000000")), xpub)
res8: String = xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
```

#### Mnemonic code (BIP39)

```shell
mvn scala:console

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import scodec.bits._
import scodec.bits._

scala> import MnemonicCode._
import MnemonicCode._

scala> val mnemonics = toMnemonics(hex"77c2b00716cec7213839159e404db50d")
mnemonics: List[String] = List(jelly, better, achieve, collect, unaware, mountain, thought, cargo, oxygen, act, hood, bridge)

scala> val seed = toSeed(mnemonics, "TREZOR")
seed: scodec.bits.ByteVector = ByteVector(64 bytes, 0xb5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff)
```
