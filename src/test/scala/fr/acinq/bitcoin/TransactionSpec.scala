package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.util

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{FlatSpec, Matchers}

object TransactionSpec {

  case class PreviousTransaction(txid: String, vout: Long, publicKeyScript: Array[Byte], privateKey: Array[Byte])

  // convert a previous tx to an tx input with an empty signature script
  def toTxIn(ptx: PreviousTransaction) = TxIn(outPoint = OutPoint(fromHexString(ptx.txid).reverse, ptx.vout), signatureScript = Array.empty[Byte], sequence = 0xFFFFFFFFL)

  // extracts data required from signature
  def toSignData(ptx: PreviousTransaction) = SignData(prevPubKeyScript = ptx.publicKeyScript, privateKey = ptx.privateKey)
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
    val ctx = Script.Context(tx2, 0)
    val runner = new Script.Runner(ctx)
    assert(runner.verifyScripts(tx2.txIn(0).signatureScript, previousTx.publicKeyScript))
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
    val ctx = Script.Context(tx2, 0)
    val runner = new Script.Runner(ctx)
    assert(runner.verifyScripts(tx2.txIn(0).signatureScript, previousTx.publicKeyScript))
  }
  it should "create and verify sign pay2pk transactions with multiple inputs and outputs" in {
    val destAddress = "moKHwpsxovDtfBJyoXpof21vvWooBExutV"
    val destAmount = 3000000

    val changeAddress = "mvHPesWqLXXy7hntNa7vbAoVwqN5PnrwJd"
    val changeAmount = 1700000

    val previousTx = List(
      PreviousTransaction(
        txid = "020c725ba1b6a485086ee9942d0871a7e918a778650600985009f4feb40b8a6c",
        vout = 0,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        privateKey = Address.decode("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs")._2),
      PreviousTransaction(
        txid = "f137884feb9a951bf9b159432ebb771ec76fa6e7332c06cb8a6b718148f101af",
        vout = 0,
        publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode("msCMyGGJ5eRcUgM5SQkwirVQGbGcr9oaYv")._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        privateKey = Address.decode("93NJN4mhL21FxRbfHZJ2Cou1YnrJmWNkujmZxeT7CPKauJkGv5g")._2)
    )

    // convert a previous tx to an tx input with an empty signature script
    def toTxIn(ptx: PreviousTransaction) = TxIn(outPoint = OutPoint(fromHexString(ptx.txid).reverse, ptx.vout), signatureScript = Array.empty[Byte], sequence = 0xFFFFFFFFL)

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = previousTx.map(toTxIn),
      txOut = List(
        TxOut(
          amount = destAmount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(destAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
        TxOut(
          amount = changeAmount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(changeAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))),
      lockTime = 0L
    )

    val tx1 = Transaction.sign(tx, previousTx.map(toSignData), randomize = false)
    assert(toHexString(Transaction.write(tx1)) === "01000000026c8a0bb4fef409509800066578a718e9a771082d94e96e0885a4b6a15b720c02000000006b483045022100e5510a2f15f03788ee2aeb2115edc96089596e3a0f0c1b1abfbbf069f4beedb802203faf6ec92a5a4ed2ce5fd42621be99746b57eca0eb46d322dc076080338b6c5a0121030533e1d2e9b7576fef26de1f34d67887158b7af1b040850aab6024b07925d70affffffffaf01f14881716b8acb062c33e7a66fc71e77bb2e4359b1f91b959aeb4f8837f1000000008b483045022100d3e5756f36e39a801c71c406124b3e0a66f0893a7fea46c69939b84715137c40022070a0e96e37c0a8e8c920e84fc63ed1914b4cef114a027f2d027d0a4a04b0b52d0141040081a4cce4c497d51d2f9be2d2109c00cbdef252185ca23074889604ace3504d73fd5f5aaac6423b04e776e467a948e1e79cb8793ded5f4b59c730c4460a0f86ffffffff02c0c62d00000000001976a914558c6b340f5abd22bf97b15cbc1483f8f1b54f5f88aca0f01900000000001976a914a1f93b5b00f9f5e8ade5549b58ed06cdc5c8203e88ac00000000")

    // now check that we can redeem this tx
    for (i <- 0 until tx1.txIn.length) {
      val ctx = Script.Context(tx1, i)
      val runner = new Script.Runner(ctx)
      assert(runner.verifyScripts(tx1.txIn(i).signatureScript, previousTx(i).publicKeyScript))
    }
    // the id of this tx on testnet is 882e971dbdb7b762cd07e5db016d3c81267ec5233186a31e6f40457a0a56a311
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
    toHexString(Transaction.write(signedTx)) should equal("0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000")

    // the id of this tx on testnet is e8570dd062de8e354b18f6308ff739a51f25db75563c4ee2bc5849281263528f

    // redeem tx
    signedTx.txIn.zipWithIndex.map {
      case (txin, index) =>
        val ctx = Script.Context(signedTx, index)
        val runner = new Script.Runner(ctx)
        assert(runner.verifyScripts(txin.signatureScript, previousTx(index).publicKeyScript))
    }
  }

  it should "solve transaction puzzle #1" in {
    // tx puzzle a59012de71dafa1510fd57d339ff488d50da4808c9fd4c001d6de8874d8aa26d
    val tx = Transaction.read("010000000298a4782ee3399a79f2b6a7c70f9f810986a42e819c14340fa35e813aac9681ae000000006e4830450220087ede38729e6d35e4f515505018e659222031273b7366920f393ee3ab17bc1e022100ca43164b757d1a6d1235f13200d4b5f76dd8fda4ec9fc28546b2df5b1211e8df03210275983913e60093b767e85597ca9397fb2f418e57f998d6afbbc536116085b1cb02ac91ffffffffa939fd811ba1c70a3ec3d955717418fe4a24dd5e597f7a47230674c853b7f360000000006d4830450220087ede38729e6d35e4f515505018e659222031273b7366920f393ee3ab17bc1e022100ca43164b757d1a6d1235f13200d4b5f76dd8fda4ec9fc28546b2df5b1211e8df03210275983913e60093b767e85597ca9397fb2f418e57f998d6afbbc536116085b1cb01acffffffff01a08601000000000017a9146c21ac707cb37c90794294acda011060ef0fc0118700000000")
    val previousTxMap = Map(
      "ae8196ac3a815ea30f34149c812ea48609819f0fc7a7b6f2799a39e32e78a498" -> Transaction.read("01000000015a7005f8a0792562bd20b9eff51c09f3e9e6522174c04098762eab1be1afc057000000006b4830450221009c290467721372d171f0d888bb193b70e6c07b116112ef23483ecbe030938636022075ce1f6be389288a4ed7c81725836a2700b539db85aeb757160c950a78fa29c6012103bc9d9e9b50db4fc3f1eb93b9a3e2cc22e179dab4df22179a34413f86078444a6ffffffff02a08601000000000017a914827fe37ec405346ad4e995323cea83559537b89e87f8e03500000000001976a914f21d36cb22c671a4b022bc953890bb9c45820a1c88ac00000000"),
      "60f3b753c8740623477a7f595edd244afe18747155d9c33e0ac7a11b81fd39a9" -> Transaction.read("0100000001ae9e6387e20d0fc30aa043ed735e33e805200d65e9d33ab503913f7436001e6b000000006b483045022100b5e73e71be331971d57ad6d804020a70a88c5617d72584d2ec76f327316da8b3022014c0d150d67847cc9c3731390691309f0465e46f4c20ee17aafc13794f8d5152012103de3d3c06403ba70b3efd5b139eb09aff8b8260bfe838a831a44666a794f5e84dffffffff02a08601000000000017a91417be79cf51aa88feebb0a25e9d6a153ead585e5987583c3900000000001976a914285fb1890240afe00b852d1b6eab49a767bc462288ac00000000")
    )
    val results = for (i <- 0 until tx.txIn.length) yield {
      val prevOutputScript = previousTxMap(tx.txIn(i).outPoint.txid).txOut(tx.txIn(i).outPoint.index.toInt).publicKeyScript
      val ctx = new Script.Context(tx, i)
      val runner = new Script.Runner(ctx)
      val result = runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript)
      result
    }

    assert(results.find(!_).isEmpty)
  }

  it should "solve transaction puzzle #2" in {
    // tx puzzle 61d47409a240a4b67ce75ec4dffa30e1863485f8fe64a6334410347692f9e60e
    val tx = Transaction.read("01000000012edfb7a1a41b61e46eae1032c38d8792eacb79f7a6599dd24372f4a3e88a31700000000006030000800191ffffffff010000000000000000016a00000000")
    val previousTxMap = Map(
      "70318ae8a3f47243d29d59a6f779cbea92878dc33210ae6ee4611ba4a1b7df2e" -> Transaction.read("010000000192cad3c8e41d1e2f1baf6f8a991c3db6bf67a60c49e963beb44f8e41a78073dd010000008b48304502203b4cb2c60cd688129ec89da31464ce9ce07da56125425afdf9fd67559e708b3c0221008174b7a26787a8eb30460a699f584518351a741bc37775dc702d7f14e8f53e340141043a58cccd11db5dfc34e1433eef0b2b3bf6b947113d5e45562a095781663c919dda444017ab9a7c0e458478e7ef3edf5233eb476c1cb62ecfbb03bc4e22e40333ffffffff0250c300000000000017a914bb89dd62e80d1801df9aa570769b012f246c4f6d8730ee9a00000000001976a91463e8c29bfd51ee98778481c920bb6d288a220f9188ac00000000")
    )
    val results = for (i <- 0 until tx.txIn.length) yield {
      val prevOutputScript = previousTxMap(tx.txIn(i).outPoint.txid).txOut(tx.txIn(i).outPoint.index.toInt).publicKeyScript
      val ctx = new Script.Context(tx, i)
      val runner = new Script.Runner(ctx)
      val result = runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript)
      result
    }

    assert(results.find(!_).isEmpty)
  }
}
