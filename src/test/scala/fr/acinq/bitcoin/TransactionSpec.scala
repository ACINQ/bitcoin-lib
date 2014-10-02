package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.util

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{FlatSpec, Matchers}

object TransactionSpec {

  case class PreviousTransaction(txid: String, vout: Long, publicKeyScript: Array[Byte], privateKey: Array[Byte])

}

@RunWith(classOf[JUnitRunner])
class TransactionSpec extends FlatSpec with Matchers {

  import fr.acinq.bitcoin.TransactionSpec._

  "Bitcoins library" should "create and sign transaction" in {
    val srcTx = fromHexString("dcd82df7b26f0eacd226b8fbd366672c854284ba8080f79e1307138c7f1a1f6d".sliding(2, 2).toList.reverse.mkString("")) // for some reason it has to be reversed
    val amount = 9000000 // amount in satoshi
    val vout = 0 // output index
    val destAdress = fromHexString("76a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac")
    val out = new ByteArrayOutputStream()
    writeUInt32(1, out) //version
    writeVarint(1, out) // nb of inputs
    out.write(srcTx) // tx in id
    writeUInt32(vout, out)
    writeScript(fromHexString("76a914ea2902457015b386bd2323b2b99591b96138d62a88ac"), out) //scriptPubKey of prev tx for signing
    writeUInt32(0xffffffff, out) // sequence
    writeVarint(1, out) // number of outputs
    writeUInt64(amount, out)
    writeScript(destAdress, out) //output script
    writeUInt32(0, out)
    writeUInt32(1, out) // hash code type
    val serialized = out.toByteArray
    val hashed = Crypto.hash256(serialized)
    val pkey_encoded = Base58.decode("92f9274aR3s6zd1vuAgxquv4KP5S5thJadF3k54NHuTV4fXL1vW")
    val pkey = pkey_encoded.slice(1, pkey_encoded.size - 4)
    val (r, s) = Crypto.sign(hashed, pkey, randomize = false)
    val sig = Crypto.encodeSignature(r, s) // DER encoded
    val sigOut = new ByteArrayOutputStream()
    writeUInt8(sig.length + 1, sigOut) // +1 because of the hash code
    sigOut.write(sig)
    writeUInt8(1, sigOut) // hash code type
    val pub = Crypto.publicKeyFromPrivateKey(pkey)
    writeUInt8(pub.length, sigOut)
    sigOut.write(pub)
    val sigScript = sigOut.toByteArray

    val signedOut = new ByteArrayOutputStream()
    writeUInt32(1, signedOut) //version
    writeVarint(1, signedOut) // nb of inputs
    signedOut.write(srcTx) // tx in id
    writeUInt32(vout, signedOut) // output index
    writeScript(sigScript, signedOut)
    writeUInt32(0xffffffff, signedOut) // sequence
    writeVarint(1, signedOut) // number of outputs
    writeUInt64(amount, signedOut) // amount in satoshi
    writeScript(destAdress, signedOut) //output script
    writeUInt32(0, signedOut)
    assert(toHexString(signedOut.toByteArray) === "01000000016d1f1a7f8c1307139ef78080ba8442852c6766d3fbb826d2ac0e6fb2f72dd8dc000000008b483045022100bdd23d0f98a4173a64fa432b8bf4ac41261a671f2c6c690d57ac839866d78bb202207bddb87ca95c9cef45de30a75144e5513571aa7938635b9e051b1c20f01088a60141044aec194c55c97f4519535f50f5539c6915045ecb79a36281dee6db55ffe1ad2e55f4a1c0e0950d3511e8f205b45cafa348a4a2ab2359246cb3c93f6532c4e8f5ffffffff0140548900000000001976a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac00000000")
  }
  it should "read and write transactions" in {
    val hex = "0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000"
    val tx = Transaction.read(fromHexString(hex))
    assert(toHexString(Transaction.write(tx)) === hex)
  }
  it should "create and verify pay2pk transactions with 1 input/1 output" in {
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val amount = 10000

    val previousTx = PreviousTransaction(
      txid = "dd2218b50eb64b0d1d0d2d4c31c1a9308966e22ebebe0ffae7035b592e39bc14",
      vout = 0,
      publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
      privateKey = Address.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")._2
    )
    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(
          OutPoint(hash = fromHexString(previousTx.txid).reverse, previousTx.vout),
          signatureScript = previousTx.publicKeyScript,
          sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(
          amount = amount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))
      ),
      lockTime = 0L
    )

    // step #2: serialize transaction and add SIGHASHTYPE
    val serializedTx1AndHashType = Transaction.write(tx1) ++ writeUInt32(1)

    // step #3: hash the result
    val hashed = Crypto.hash256(serializedTx1AndHashType)

    // step #4: sign transaction hash
    val (r, s) = Crypto.sign(hashed, previousTx.privateKey.take(32), randomize = false)
    val sig = Crypto.encodeSignature(r, s) // DER encoded

    // this is the public key that is associated to the private key we used for signing
    val publicKey = Crypto.publicKeyFromPrivateKey(previousTx.privateKey)
    // we check that is really is the public key that is encoded in the address the previous tx was paid to
    val providedHash = Address.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")._2
    val computedHash = Crypto.hash160(publicKey)
    assert(util.Arrays.equals(providedHash, computedHash))

    // step #5: now we replace the sigscript with sig + public key, and we get what would be sent to the btc network
    val tx2 = tx1.copy(txIn = List(
      TxIn(
        OutPoint(hash = fromHexString(previousTx.txid).reverse, previousTx.vout),
        signatureScript = Script.write(OP_PUSHDATA(sig :+ 1.toByte) :: OP_PUSHDATA(publicKey) :: Nil),
        sequence = 0xFFFFFFFFL
      )
    ))

    // check signature
    val (r1, s1) = Crypto.decodeSignature(sig)
    assert(Crypto.verifySignature(hashed, (r1, s1), publicKey))

    // check script
    val ctx = Script.Context(tx2, 0, previousTx.publicKeyScript)
    def execute = Script.execute(ctx) _
    val stack = execute(Script.parse(tx2.txIn(0).signatureScript), List())
    val stack1 = execute(Script.parse(previousTx.publicKeyScript), stack)
    val List(Array(check)) = stack1
    assert(check === 1)
  }
  // same as above, but using Transaction.sign() instead of signing the tx manually
  it should "create and verify pay2pk transactions with 1 input/1 output using helper method" in {
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val amount = 10000

    val previousTx = PreviousTransaction(
      txid = "dd2218b50eb64b0d1d0d2d4c31c1a9308966e22ebebe0ffae7035b592e39bc14",
      vout = 0,
      publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
      privateKey = Address.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")._2
    )
    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(
          OutPoint(hash = fromHexString(previousTx.txid).reverse, previousTx.vout),
          signatureScript = previousTx.publicKeyScript,
          sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(
          amount = amount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))
      ),
      lockTime = 0L
    )

    // step #2: sign the tx
    val tx2 = Transaction.sign(tx1, List(SignData(previousTx.publicKeyScript, previousTx.privateKey)))

    // redeem the tx
    val ctx = Script.Context(tx2, 0, previousTx.publicKeyScript)
    def execute = Script.execute(ctx) _
    val stack = execute(Script.parse(tx2.txIn(0).signatureScript), List())
    val stack1 = execute(Script.parse(previousTx.publicKeyScript), stack)
    val List(Array(check)) = stack1
    assert(check === 1)
  }
  it should "create and verify sign pay2pk transactions with multiple inputs and outputs" in {
    val to = "n4FiyibS6hUPnsFx4zyUghgZ9Lc9k3QtuK"
    val amount = 20000

    val previousTx = List(
      PreviousTransaction(
        txid = "d8afe2f72c53d83e8037b1bf1f2b326ae90031e459bb744fb1a46cf2b2319ba7",
        vout = 0,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        privateKey = Address.decode("cSC2i7fW1oyKQVkG58nV5wBGocwaZrqJbhRzJxFYV3AoCXLeUTA5")._2),
      PreviousTransaction(
        txid = "cc97331482bdce449861843e312200f35aa6a4a07cf03574cc10e5c66c1aa1cf",
        vout = 0,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        privateKey = Address.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")._2)
    )

    // convert a previous tx to an tx input with an empty signature script
    def toTxIn(ptx: PreviousTransaction) = TxIn(outPoint = OutPoint(fromHexString(ptx.txid).reverse, ptx.vout), signatureScript = Array.empty[Byte], sequence = 0xFFFFFFFFL)

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = previousTx.map(toTxIn),
      txOut = List(TxOut(
        amount = amount,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))),
      lockTime = 0L
    )

    // create a signature script for each input
    val signatureScripts = for (i <- 0 until previousTx.length) yield {
      // replace the empty sig script by the public key script of the output this input refers to
      val tx1 = tx.copy(txIn = tx.txIn.updated(i, tx.txIn(i).copy(signatureScript = previousTx(i).publicKeyScript)))
      val hashed = Crypto.hash256(Transaction.write(tx1) ++ writeUInt32(1))
      val (r, s) = Crypto.sign(hashed, previousTx(i).privateKey.take(32), randomize = false)
      val sig = Crypto.encodeSignature(r, s) // DER encoded
      // this is the public key that is associated to the private key we used for signing
      val publicKey = Crypto.publicKeyFromPrivateKey(previousTx(i).privateKey)
      Script.write(OP_PUSHDATA(sig :+ 1.toByte) :: OP_PUSHDATA(publicKey) :: Nil)
    }

    val inputs = for (i <- 0 until previousTx.length) yield {
      tx.txIn(i).copy(signatureScript = signatureScripts(i))
    }

    val tx1 = tx.copy(txIn = inputs.toList)
    assert(toHexString(Transaction.write(tx1)) === "0100000002a79b31b2f26ca4b14f74bb59e43100e96a322b1fbfb137803ed8532cf7e2afd8000000006a473044022004f0a91f258fd7a9024a40ccb2a81245c0dd3c64eb0b329f3fbb0a8d91dae89d0220776a2eac637771f016299879ceed6329d93b702f7f3973e88f4d01695203d1a90121024df51eef1ad9c55629a10446684aa5b1841cc13550072f5a0906e8994335178dffffffffcfa11a6cc6e510cc7435f07ca0a4a65af30022313e84619844cebd82143397cc000000006b483045022100e57cd92926acfe2ba6f1bfbd58b96b55678c0a5cee445240a4060eef4397c9cf02205bbe808d10375af87cd3353612450889fcb0b4a399d64fc79bb16853588b2413012103144d434e85140d4109814ac78491ffeae384c18e2225ba109ad25ff0e46eef65ffffffff01204e0000000000001976a914f96989b054bebbe582cdce7ade128d34ce847f3988ac00000000")
  }

  it should "sign a 3-to-2 transaction with helper method" in {

    val previousTx = List(
      PreviousTransaction(// 0.01 BTC
        txid = "849516dd5a7c092c4368f6fc26bc6b61f8777ba48f2bc54a6f9e2cc85e5e4d86",
        vout = 1,
        publicKeyScript = fromHexString("76a9148c9648cab53a1fb8861daff0f2378c7b9e81a3ab88ac"),
        privateKey = Address.decode("cW6bSKtH3oMPA18cXSMR8ASHztrmbwmCyqvvN8x3Tc7WG6TyrJDg")._2),
      PreviousTransaction(// 0.002 BTC
        txid = "a9ba1666b552efdaea1dbe3c61e453a32942b788c44ddd2562d5e68806b187d5",
        vout = 0,
        publicKeyScript = fromHexString("76a9146a3e65bf746bcd7af3493e19451451a8a4da331588ac"),
        privateKey = Address.decode("93Ag8t83NW9WmPbhqLCSUNckARpbpgWtp4EWGidtj6h6pVQgGN4")._2),
      PreviousTransaction(// 0.09 BTC
        txid = "fd455bc2432d957bf48fc953c6a4a25b0486f5d7a582a99fa080b0aab462a194",
        vout = 0,
        publicKeyScript = fromHexString("76a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac"),
        privateKey = Address.decode("921vnTeSQCN7GMHdiHyaoZ1JSugTtzvg8rqyXH9HmFtBgrNDxCT")._2)
    )

    val dest1 = "n2Jrcf7cJH7wMJdhKZGVi2jaSnV2BwYE9m" //priv: 926iWgQDq5dN84BJ4q2fu4wjSSaVWFxwanE8EegzMh3vGCUBJ94
    val dest2 = "mk6kmMF5EEXksBkZxi7FniwwRgWuZuwDpo" //priv: 91r7coHBdzfgfm2p3ToJ3Bu6kcqL3BvSo5m4ENzMZzsimRKH8aq
    // 0.03 and 0.07 BTC in satoshi, meaning the fee will be (0.01+0.002+0.09)-(0.03+0.07) = 0.002
    val amount1 = 3000000
    val amount2 = 7000000

    // convert a previous tx to an tx input with an empty signature script
    def toTxIn(ptx: PreviousTransaction) = TxIn(outPoint = OutPoint(fromHexString(ptx.txid).reverse, ptx.vout), signatureScript = Array.empty[Byte], sequence = 0xFFFFFFFFL)

    // extracts data required from signature
    def toSignData(ptx: PreviousTransaction) = SignData(prevPubKeyScript = ptx.publicKeyScript, privateKey = ptx.privateKey)

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = previousTx.map(toTxIn),
      txOut = List(TxOut(
        amount = amount1,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(dest1)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
        TxOut(
          amount = amount2,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(dest2)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))),
      lockTime = 0L
    )

    val signedTx = Transaction.sign(tx, previousTx.map(toSignData), randomize = false)

    //this works because signature is not randomized
    toHexString(Transaction.write(signedTx)) should equal ("0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000")

    // the id of this tx on testnet is e8570dd062de8e354b18f6308ff739a51f25db75563c4ee2bc5849281263528f

    // redeem tx
    signedTx.txIn.zipWithIndex.map {
      case (txin, index) =>
        val ctx = Script.Context(signedTx, index, previousTx(index).publicKeyScript)
        def execute = Script.execute(ctx) _
        val stack = execute(Script.parse(txin.signatureScript), List())
        val stack1 = execute(Script.parse(previousTx(index).publicKeyScript), stack)
        val List(Array(check)) = stack1
        assert(check === 1)
    }
  }
}
