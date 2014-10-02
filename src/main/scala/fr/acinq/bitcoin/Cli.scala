package fr.acinq.bitcoin

object Cli extends App {

  var testnet = false

  def parse(arguments: List[String]): Unit = arguments match {
    case "-dscript" :: hex :: tail => println(Script.parse(fromHexString(hex)))
    case "-dtx" :: hex :: tail => println(Json.toJson(Transaction.read(fromHexString(hex)), testnet))
    case "-daddr" :: base58 :: tail => println(Address.decode(base58))
    case "-eaddr" :: hex :: version :: tail => println(Address.encode(version.toByte, fromHexString(hex)))
    case "-mkp2pkscript" :: address :: tail =>
      val (version, pkhash) = Address.decode(address)
      println(toHexString(Script.write(List(OP_DUP, OP_HASH160, OP_PUSHDATA(pkhash), OP_EQUALVERIFY, OP_CHECKSIG))))
    case "-testnet" :: tail => testnet = true; parse(tail)
  }

  parse(args.toList)
}
