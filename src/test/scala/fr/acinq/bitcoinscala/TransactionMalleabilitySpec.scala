package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.Crypto.PrivateKey
import org.scalatest.FlatSpec
import scodec.bits._

class TransactionMalleabilitySpec extends FlatSpec {
  "Transaction" should "not be malleable" in {
    // tx we want to spend
    val prevTx = Transaction.read("01000000014a1140be18e3affa32a9561a3a4a75b9ed8b965a368a6f39fc57aee97c0eb4df010000006a4730440220363ce2ad434d16d8ca4f35866432fec887526bed328ec705af3a36cef1625fce0220579c0a7c57fe8a3691c833b78de7a3886a5e66422866e5d66cfcede2b8aaaac50121024034a310a6001ea45f7c9708c2f878c8ce42d715ceeaa2cd315af9d97baf85faffffffff02d0f9a800000000001976a91450ca5b3fb8268714ef48b0d46813df337dc5d5db88ac80969800000000001976a914d59dbfeedb94e9e66bd8b91af6caad082971b1b588ac00000000")

    // private key that matches the public key the btc we sent to in the tx we want to redeem
    val privateKey = PrivateKey.fromBase58("cSjAjBx5zSuA16zhG2owyNCzkXLc7qJTz9M8aR6uK9S9QqS9P6gF", Base58.Prefix.SecretKeyTestnet)._1
    //    val (_, privateKey) = Base58Check.decode("cSjAjBx5zSuA16zhG2owyNCzkXLc7qJTz9M8aR6uK9S9QqS9P6gF")

    // public key we want to sent btc to
    val publicKey = hex"03f1c059112166776c70367cc1a83851c6224e45f6fe3944442f7961072212f954"
    val publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(publicKey)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil

    // step #1: create an unsigned tx that sends the 2nd output of prevTx to our publicKey
    val unsignedTx = Transaction(version = 1,
      txIn = List(
        TxIn(
          OutPoint(prevTx, 1),
          ByteVector.empty, // empty sig script
          0xffffffffL
        )),
      txOut = List(
        TxOut(
          amount = 1000 sat,
          publicKeyScript = publicKeyScript)
      ),
      lockTime = 0)


    // step #2: sign the unsigned tx
    // signature script: push signature and public key
    val sig = Transaction.signInput(unsignedTx, 0, prevTx.txOut(1).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, privateKey)
    val signatureScript = OP_PUSHDATA(sig) :: OP_PUSHDATA(privateKey.publicKey) :: Nil

    val tx1 = Transaction(version = 1,
      txIn = List(
        TxIn(
          OutPoint(prevTx, 1),
          signatureScript,
          0xffffffffL
        )),
      txOut = unsignedTx.txOut,
      lockTime = 0)

    Transaction.correctlySpends(tx1, Seq(prevTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)

    // step #3: modify tx2 to obtain another valid tx that sends the same output to the same address, without knowing the private key
    // this modified tx would have a different tx id. this is something anyone could do. it means that you cannot rely
    // on tx ids before they've been mined.
    val tx2 = Transaction(version = 1,
      txIn = List(
        TxIn(
          OutPoint(prevTx, 1),
          OP_NOP :: signatureScript,
          0xffffffffL
        )),
      txOut = tx1.txOut,
      lockTime = 0)

    assert(tx1.txid != tx2.txid)
    Transaction.correctlySpends(tx2, Seq(prevTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // but it would fail if we enforce the "sig script should only push data" rule
    intercept[RuntimeException] {
      Transaction.correctlySpends(tx2, Seq(prevTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS | ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY)
    }
  }
}
