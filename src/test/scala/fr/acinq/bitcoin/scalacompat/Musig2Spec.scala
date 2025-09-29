package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import fr.acinq.bitcoin.{ScriptFlags, SigHash}
import org.scalatest.FunSuite
import scodec.bits.{ByteVector, HexStringSyntax}

import scala.util.Random

class Musig2Spec extends FunSuite {

  test("use musig2 to replace multisig 2-of-2") {
    val alicePrivKey = PrivateKey(hex"0101010101010101010101010101010101010101010101010101010101010101")
    val alicePubKey = alicePrivKey.publicKey
    val bobPrivKey = PrivateKey(hex"0202020202020202020202020202020202020202020202020202020202020202")
    val bobPubKey = bobPrivKey.publicKey

    // Alice and Bob exchange public keys and agree on a common aggregated key.
    val internalPubKey = Musig2.aggregateKeys(Seq(alicePubKey, bobPubKey))

    // This tx sends to a taproot script that doesn't contain any script path.
    val tx = Transaction(2, Nil, Seq(TxOut(10_000 sat, Script.pay2tr(internalPubKey, scripts_opt = None))), 0)
    // This tx spends the previous tx with Alice and Bob's signatures.
    val spendingTx = Transaction(2, Seq(TxIn(OutPoint(tx, 0), ByteVector.empty, 0)), Seq(TxOut(10_000 sat, Script.pay2wpkh(alicePubKey))), 0)

    // The first step of a musig2 signing session is to exchange nonces.
    // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
    val aliceNonce = Musig2.generateNonce(ByteVector32(ByteVector(Random.nextBytes(32))), Left(alicePrivKey), Seq(alicePubKey, bobPubKey), None, None)
    val bobNonce = Musig2.generateNonce(ByteVector32(ByteVector(Random.nextBytes(32))), Right(bobPrivKey.publicKey), Seq(alicePubKey, bobPubKey), None, None)

    // Once they have each other's public nonce, they can produce partial signatures.
    val publicNonces = Seq(aliceNonce, bobNonce).map(_.publicNonce)
    val Right(aliceSig) = Musig2.signTaprootInput(alicePrivKey, spendingTx, 0, tx.txOut, Seq(alicePubKey, bobPubKey), aliceNonce.secretNonce, publicNonces, scriptTree_opt = None)
    assert(Musig2.verifyTaprootSignature(aliceSig, aliceNonce.publicNonce, alicePubKey, spendingTx, 0, tx.txOut, Seq(alicePubKey, bobPubKey), publicNonces, scriptTree_opt = None))
    val Right(bobSig) = Musig2.signTaprootInput(bobPrivKey, spendingTx, 0, tx.txOut, Seq(alicePubKey, bobPubKey), bobNonce.secretNonce, publicNonces, scriptTree_opt = None)
    assert(Musig2.verifyTaprootSignature(bobSig, bobNonce.publicNonce, bobPubKey, spendingTx, 0, tx.txOut, Seq(alicePubKey, bobPubKey), publicNonces, scriptTree_opt = None))

    // Once they have each other's partial signature, they can aggregate them into a valid signature.
    val Right(aggregateSig) = Musig2.aggregateTaprootSignatures(Seq(aliceSig, bobSig), spendingTx, 0, tx.txOut, Seq(alicePubKey, bobPubKey), publicNonces, scriptTree_opt = None)

    // This tx looks like any other tx that spends a p2tr output, with a single signature.
    val signedSpendingTx = spendingTx.updateWitness(0, Script.witnessKeyPathPay2tr(aggregateSig))
    Transaction.correctlySpends(signedSpendingTx, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("swap-in-potentiam example with musig2 and taproot") {
    val userPrivateKey = PrivateKey(hex"0101010101010101010101010101010101010101010101010101010101010101")
    val userPublicKey = userPrivateKey.publicKey
    val serverPrivateKey = PrivateKey(hex"0202020202020202020202020202020202020202020202020202020202020202")
    val serverPublicKey = serverPrivateKey.publicKey
    val userRefundPrivateKey = PrivateKey(hex"0303030303030303030303030303030303030303030303030303030303030303")
    val refundDelay = 25920

    // The redeem script is just the refund script. it is generated from this policy: and_v(v:pk(user),older(refundDelay)).
    // It does not depend upon the user's or server's key, just the user's refund key and the refund delay.
    val redeemScript = Seq(OP_PUSHDATA(userRefundPrivateKey.xOnlyPublicKey()), OP_CHECKSIGVERIFY, OP_PUSHDATA(Script.encodeNumber(refundDelay)), OP_CHECKSEQUENCEVERIFY)
    val scriptTree = ScriptTree.Leaf(redeemScript)

    // The internal pubkey is the musig2 aggregation of the user's and server's public keys: it does not depend upon the user's refund's key.
    val aggregatedKey = Musig2.aggregateKeys(Seq(userPublicKey, serverPublicKey))
    // It is tweaked with the script's merkle root to get the pubkey that will be exposed.
    val pubkeyScript = Script.pay2tr(aggregatedKey, Some(scriptTree))

    val swapInTx = Transaction(
      version = 2,
      txIn = Nil,
      txOut = Seq(TxOut(10_000 sat, pubkeyScript)),
      lockTime = 0
    )

    // The transaction can be spent if the user and the server produce a signature.
    {
      val tx = Transaction(
        version = 2,
        txIn = Seq(TxIn(OutPoint(swapInTx, 0), ByteVector.empty, 0xFFFFFFFD)),
        txOut = Seq(TxOut(10_000 sat, Script.pay2wpkh(userPublicKey))),
        lockTime = 0
      )
      // The first step of a musig2 signing session is to exchange nonces.
      // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
      val userNonce = Musig2.generateNonce(ByteVector32(ByteVector(Random.nextBytes(32))), Left(userPrivateKey), Seq(userPublicKey, serverPublicKey), None, None)
      val serverNonce = Musig2.generateNonce(ByteVector32(ByteVector(Random.nextBytes(32))), Right(serverPrivateKey.publicKey), Seq(userPublicKey, serverPublicKey), None, None)

      // Once they have each other's public nonce, they can produce partial signatures.
      val publicNonces = Seq(userNonce, serverNonce).map(_.publicNonce)
      val Right(userSig) = Musig2.signTaprootInput(userPrivateKey, tx, 0, swapInTx.txOut, Seq(userPublicKey, serverPublicKey), userNonce.secretNonce, publicNonces, Some(scriptTree))
      assert(Musig2.verifyTaprootSignature(userSig, userNonce.publicNonce, userPublicKey, tx, 0, swapInTx.txOut, Seq(userPublicKey, serverPublicKey), publicNonces, Some(scriptTree)))
      val Right(serverSig) = Musig2.signTaprootInput(serverPrivateKey, tx, 0, swapInTx.txOut, Seq(userPublicKey, serverPublicKey), serverNonce.secretNonce, publicNonces, Some(scriptTree))
      assert(Musig2.verifyTaprootSignature(serverSig, serverNonce.publicNonce, serverPublicKey, tx, 0, swapInTx.txOut, Seq(userPublicKey, serverPublicKey), publicNonces, Some(scriptTree)))

      // Once they have each other's partial signature, they can aggregate them into a valid signature.
      val Right(sig) = Musig2.aggregateTaprootSignatures(Seq(userSig, serverSig), tx, 0, swapInTx.txOut, Seq(userPublicKey, serverPublicKey), publicNonces, Some(scriptTree))
      val signedTx = tx.updateWitness(0, Script.witnessKeyPathPay2tr(sig))
      Transaction.correctlySpends(signedTx, Seq(swapInTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    // Or it can be spent with only the user's signature, after a delay.
    {
      val tx = Transaction(
        version = 2,
        txIn = Seq(TxIn(OutPoint(swapInTx, 0), ByteVector.empty, refundDelay)),
        txOut = Seq(TxOut(10_000 sat, Script.pay2wpkh(userPublicKey))),
        lockTime = 0
      )
      val sig = Transaction.signInputTaprootScriptPath(userRefundPrivateKey, tx, 0, swapInTx.txOut, SigHash.SIGHASH_DEFAULT, scriptTree.hash())
      val witness = Script.witnessScriptPathPay2tr(aggregatedKey, scriptTree, ScriptWitness(Seq(sig)), scriptTree)
      val signedTx = tx.updateWitness(0, witness)
      Transaction.correctlySpends(signedTx, Seq(swapInTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
  }

  test("generate nonce with counter") {
    val sk = PrivateKey(ByteVector.fromValidHex("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54"))
    val nonce = Musig2.generateNonceWithCounter(0, sk, Seq(sk.publicKey), None, None)
    assert(nonce.publicNonce.data == hex"0271efb262c0535e921efacacd30146fa93f193689e4974d5348fa9d909d90000702a049680ef3f6acfb12320297df31d3a634214491cbeebacef5acdf13f8f61cc2")
  }

}
