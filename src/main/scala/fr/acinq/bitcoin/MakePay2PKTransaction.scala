package fr.acinq.bitcoin

object MakePay2PKTransaction extends App {

  case class Config(txfrom: String = "", vout: Long = 0, from: String = "", to: String = "", key: String = "", amount: Long = 0, testnet: Boolean = false)

  val parser = new scopt.OptionParser[Config]("MakePay2PKTransaction") {
    head("MakePay2PKTransaction")
    opt[String]("txfrom") required() action { (x, c) => c.copy(txfrom = x)} text ("input transaction id")
    opt[Long]("vout") required() action { (x, c) => c.copy(vout = x)} text ("output index in the input transaction")
    opt[String]('i', "from") required() action { (x, c) => c.copy(from = x)} text ("address the btc were sent to in the input tx")
    opt[String]('o', "to") required() action { (x, c) => c.copy(to = x)} text ("output address")
    opt[String]('k', "key") required() action { (x, c) => c.copy(key = x)} text ("private key used for signing (in base58 format)")
    opt[Long]('a', "amount") required() action { (x, c) => c.copy(amount = x)} text ("amount to transfer")
    opt[Unit]("testnet") optional() action { (_, c) => c.copy(testnet = true)} text ("use testnet")
  }

  parser.parse(args, Config()) map { config =>

    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(
          OutPoint(hash = fromHexString(config.txfrom).reverse, config.vout),
          signatureScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(config.from)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
          sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(
          amount = config.amount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Address.decode(config.to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))
      ),
      lockTime = 0L
    )

    val serializedTx1AndHashType = Transaction.write(tx1) ++ writeUInt32(1)
    val hashed = Crypto.hash256(serializedTx1AndHashType)

    val (_, pkey) = Address.decode(config.key)
    val (r, s) = Crypto.sign(hashed, pkey.take(32))
    val sig = Crypto.encodeSignature(r, s) // DER encoded

    val publicKey = Crypto.publicKeyFromPrivateKey(pkey)

    val tx2 = tx1.copy(txIn = List(
      TxIn(
        OutPoint(hash = fromHexString(config.txfrom).reverse, config.vout),
        signatureScript = Script.write(OP_PUSHDATA(sig :+ 1.toByte) :: OP_PUSHDATA(publicKey) :: Nil),
        sequence = 0xFFFFFFFFL
      )
    ))

    val result = toHexString(Transaction.write(tx2))
    println(result)

  } getOrElse {
    // arguments are bad, error message will have been displayed
  }
}
