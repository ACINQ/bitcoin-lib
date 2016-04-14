package fr.acinq.bitcoin

import java.io._
import java.math.BigInteger
import java.net.{Inet4Address, Inet6Address, InetAddress}
import java.util

import com.typesafe.config.ConfigFactory
import fr.acinq.bitcoin.Script.Runner

import scala.collection.mutable.ArrayBuffer

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */

object BinaryData {
  def apply(hex: String): BinaryData = hex
}

case class BinaryData(data: Seq[Byte]) {
  def length = data.length

  override def toString = toHexString(data)
}

object Protocol {
  /**
   * basic serialization functions
   */

  val PROTOCOL_VERSION = ConfigFactory.load().getLong("bitcoin-lib.protocol-version")

  def uint8(blob: Seq[Byte]) = blob(0) & 0xffl

  def uint8(input: InputStream): Long = input.read().toLong

  def writeUInt8(input: Long, out: OutputStream): Unit = out.write((input & 0xff).asInstanceOf[Int])

  def writeUInt8(input: Int, out: OutputStream): Unit = writeUInt8(input.toLong, out)

  def writeUInt8(input: Int): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    writeUInt8(input, out)
    out.toByteArray
  }

  def uint16(a: Int, b: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8)

  def uint16BigEndian(a: Int, b: Int): Long = ((b & 0xffl) << 0) | ((a & 0xffl) << 8)

  def uint16(blob: Seq[Byte]): Long = uint16(blob(0), blob(1))

  def uint16BigEndian(blob: Array[Byte]): Long = uint16BigEndian(blob(0), blob(1))

  def uint16(input: InputStream): Long = uint16(input.read(), input.read())

  def uint16BigEndian(input: InputStream): Long = uint16BigEndian(input.read(), input.read())

  def writeUInt16(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >> 8) & 0xff, out)
  }

  def writeUInt16(input: Int, out: OutputStream): Unit = writeUInt16(input.toLong, out)

  def writeUInt16BigEndian(input: Long, out: OutputStream): Unit = {
    writeUInt8((input >> 8) & 0xff, out)
    writeUInt8((input) & 0xff, out)
  }

  def writeUInt16BigEndian(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(2)
    writeUInt16BigEndian(input, out)
    out.toByteArray
  }

  def writeUInt16BigEndian(input: Int): Array[Byte] = writeUInt16BigEndian(input.toLong)

  def uint32(a: Int, b: Int, c: Int, d: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8) | ((c & 0xffl) << 16) | ((d & 0xffl) << 24)

  def uint32(blob: Seq[Byte]): Long = uint32(blob(0), blob(1), blob(2), blob(3))

  def uint32(input: InputStream): Long = {
    val blob = new Array[Byte](4)
    input.read(blob)
    uint32(blob)
  }

  def writeUInt32(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 24) & 0xff, out)
  }

  def writeUInt32(input: Int, out: OutputStream): Unit = writeUInt32(input.toLong, out)

  def writeUInt32(input: Int): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    writeUInt32(input, out)
    out.toByteArray
  }

  def writeUInt32(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(4)
    writeUInt32(input, out)
    out.toByteArray
  }

  def writeUInt32BigEndian(input: Long, out: OutputStream): Unit = {
    writeUInt8((input >>> 24) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input) & 0xff, out)
  }

  def writeUInt32BigEndian(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(4)
    writeUInt32BigEndian(input, out)
    out.toByteArray
  }

  def writeUInt32BigEndian(input: Int): Array[Byte] = writeUInt32BigEndian(input.toLong)

  def uint64(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int): Long = ((a & 0xffl) << 0) | ((b & 0xffl) << 8) | ((c & 0xffl) << 16) | ((d & 0xffl) << 24) | ((e & 0xffl) << 32) | ((f & 0xffl) << 40) | ((g & 0xffl) << 48) | ((h & 0xffl) << 56)

  def uint64(blob: Seq[Byte]): Long = uint64(blob(0), blob(1), blob(2), blob(3), blob(4), blob(5), blob(6), blob(7))

  def uint64(input: InputStream): Long = uint64(input.read(), input.read(), input.read(), input.read(), input.read(), input.read(), input.read(), input.read())

  def writeUInt64(input: Long, out: OutputStream): Unit = {
    writeUInt8((input) & 0xff, out)
    writeUInt8((input >>> 8) & 0xff, out)
    writeUInt8((input >>> 16) & 0xff, out)
    writeUInt8((input >>> 24) & 0xff, out)
    writeUInt8((input >>> 32) & 0xff, out)
    writeUInt8((input >>> 40) & 0xff, out)
    writeUInt8((input >>> 48) & 0xff, out)
    writeUInt8((input >>> 56) & 0xff, out)
  }

  def writeUInt64(input: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream(8)
    writeUInt64(input, out)
    out.toByteArray
  }

  def writeUInt64(input: Int, out: OutputStream): Unit = writeUInt64(input.toLong, out)

  def varint(blob: Array[Byte]): Long = varint(new ByteArrayInputStream(blob))

  def varint(input: InputStream): Long = input.read() match {
    case value if value < 0xfd => value
    case 0xfd => uint16(input)
    case 0xfe => uint32(input)
    case 0xff => uint64(input)
  }

  def writeVarint(input: Int, out: OutputStream): Unit = writeVarint(input.toLong, out)

  def writeVarint(input: Long, out: OutputStream): Unit = {
    if (input < 0xfdL) writeUInt8(input, out)
    else if (input < 65535L) {
      writeUInt8(0xfdL, out)
      writeUInt16(input, out)
    }
    else if (input < 1048576L) {
      writeUInt8(0xfeL, out)
      writeUInt32(input, out)
    }
    else {
      writeUInt8(0xffL, out)
      writeUInt64(input, out)
    }
  }

  def bytes(input: InputStream, size: Long): Array[Byte] = bytes(input, size.toInt)

  def bytes(input: InputStream, size: Int): Array[Byte] = {
    val blob = new Array[Byte](size)
    if (size > 0) {
      val count = input.read(blob)
      if (count < size) throw new IOException("not enough data to read from")
    }
    blob
  }

  def varstring(input: InputStream): String = {
    val length = varint(input)
    new String(bytes(input, length), "UTF-8")
  }

  def writeVarstring(input: String, out: OutputStream) = {
    writeVarint(input.length, out)
    out.write(input.getBytes("UTF-8"))
  }

  def hash(input: InputStream): Array[Byte] = bytes(input, 32) // a hash is always 256 bits

  def script(input: InputStream): BinaryData = {
    val length = varint(input) // read size
    bytes(input, length.toInt) // read bytes
  }

  //def writeScript(input: BinaryData, out: OutputStream): Unit = writeScript(input.toArray, out)

  def writeScript(input: Array[Byte], out: OutputStream): Unit = {
    writeVarint(input.length.toLong, out)
    out.write(input)
  }

  implicit val txInSer = TxIn
  implicit val txOutSer = TxOut
  implicit val scriptWitnessSer = ScriptWitness
  implicit val txSer = Transaction
  implicit val networkAddressWithTimestampSer = NetworkAddressWithTimestamp
  implicit val inventoryVectorOutSer = InventoryVector

  def readCollection[T](input: InputStream, maxElement: Option[Int], protocolVersion: Long)(implicit ser: BtcMessage[T]) : Seq[T] =
    readCollection(input, ser.read, maxElement, protocolVersion)

  def readCollection[T](input: InputStream, protocolVersion: Long)(implicit ser: BtcMessage[T]): Seq[T] =
    readCollection(input, None, protocolVersion)(ser)

  def readCollection[T](input: InputStream, reader: (InputStream, Long) => T, maxElement: Option[Int], protocolVersion: Long) : Seq[T] = {
    val count = varint(input)
    maxElement.map(max => require(count <= max, "invalid length"))
    val items = ArrayBuffer.empty[T]
    for (i <- 1L to count) {
      items += reader(input, protocolVersion)
    }
    items.toSeq
  }

  def readCollection[T](input: InputStream, reader: (InputStream, Long) => T, protocolVersion: Long) : Seq[T] = readCollection(input, reader, None, protocolVersion)

  def writeCollection[T](seq: Seq[T], out: OutputStream, protocolVersion: Long)(implicit ser: BtcMessage[T]) : Unit = {
    writeVarint(seq.length, out)
    seq.map(t => ser.write(t, out, protocolVersion))
  }

  def writeCollection[T](seq: Seq[T], writer: (T, OutputStream, Long) => Unit, out: OutputStream, protocolVersion: Long) : Unit = {
    writeVarint(seq.length, out)
    seq.map(t => writer(t, out, protocolVersion))
  }
}

import Protocol._

trait BtcMessage[T] {
  /**
   * write a message to a stream
    *
    * @param t message
   * @param out output stream
   */
  def write(t: T, out: OutputStream, protocolVersion: Long): Unit

  def write(t:T, out: OutputStream): Unit = write(t, out, PROTOCOL_VERSION)

  /**
   * write a message to a byte array
    *
    * @param t message
   * @return a serialized message
   */
  def write(t: T, protocolVersion: Long): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    write(t, out, protocolVersion)
    out.toByteArray
  }

  def write(t: T): Array[Byte] = write(t, PROTOCOL_VERSION)

    /**
   * read a message from a stream
      *
      * @param in input stream
   * @return a deserialized message
   */
  def read(in: InputStream, protocolVersion: Long): T

  def read(in: InputStream): T = read(in, PROTOCOL_VERSION)

  /**
   * read a message from a byte array
    *
    * @param in serialized message
   * @return a deserialized message
   */
  def read(in: Seq[Byte], protocolVersion: Long): T = read(new ByteArrayInputStream(in.toArray), protocolVersion)

  def read(in: Seq[Byte]): T = read(in, PROTOCOL_VERSION)

  /**
   * read a message from a hex string
    *
    * @param in message binary data in hex format
   * @return a deserialized message of type T
   */
  def read(in: String, protocolVersion: Long): T = read(fromHexString(in), protocolVersion)

  def read(in: String): T = read(in, PROTOCOL_VERSION)

  def validate(t: T): Unit = {}
}


object OutPoint extends BtcMessage[OutPoint] {
  def apply(tx: Transaction, index: Int) = new OutPoint(tx.hash, index)

  override def read(input: InputStream, protocolVersion: Long): OutPoint = OutPoint(hash(input), uint32(input))

  override def write(input: OutPoint, out: OutputStream, protocolVersion: Long) = {
    out.write(input.hash)
    writeUInt32(input.index, out)
  }

  def isCoinbase(input: OutPoint) = input.index == 0xffffffffL && input.hash == Hash.Zeroes

  def isNull(input: OutPoint) = isCoinbase(input)

}

/**
 * an out point is a reference to a specific output in a specific transaction that we want to claim
  *
  * @param hash reversed sha256(sha256(tx)) where tx is the transaction we want to refer to
 * @param index index of the output in tx that we want to refer to
 */
case class OutPoint(hash: BinaryData, index: Long) {
  require(hash.length == 32)
  require(index >= -1)

  /**
   *
   * @return the id of the transaction this output belongs to
   */
  def txid = toHexString(hash.data.reverse)
}

object TxIn extends BtcMessage[TxIn] {
  def apply(outPoint: OutPoint, signatureScript: Seq[ScriptElt], sequence: Long): TxIn = new TxIn(outPoint, Script.write(signatureScript), sequence)

  /* Setting nSequence to this value for every input in a transaction disables nLockTime. */
  val SEQUENCE_FINAL = 0xffffffffL

  /* Below flags apply in the context of BIP 68*/
  /* If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time. */
  val SEQUENCE_LOCKTIME_DISABLE_FLAG = (1L << 31)

  /* If CTxIn::nSequence encodes a relative lock-time and this flag
   * is set, the relative lock-time has units of 512 seconds,
   * otherwise it specifies blocks with a granularity of 1. */
  val SEQUENCE_LOCKTIME_TYPE_FLAG = (1L << 22)

  /* If CTxIn::nSequence encodes a relative lock-time, this mask is
   * applied to extract that lock-time from the sequence field. */
  val SEQUENCE_LOCKTIME_MASK = 0x0000ffffL

  /* In order to use the same number of bits to encode roughly the
   * same wall-clock duration, and because blocks are naturally
   * limited to occur every 600s on average, the minimum granularity
   * for time-based relative lock-time is fixed at 512 seconds.
   * Converting from CTxIn::nSequence to seconds is performed by
   * multiplying by 512 = 2^9, or equivalently shifting up by
   * 9 bits. */
  val SEQUENCE_LOCKTIME_GRANULARITY = 9

  override def read(input: InputStream, protocolVersion: Long): TxIn = TxIn(outPoint = OutPoint.read(input), signatureScript = script(input), sequence = uint32(input))

  override def write(input: TxIn, out: OutputStream, protocolVersion: Long) = {
    OutPoint.write(input.outPoint, out)
    writeScript(input.signatureScript, out)
    writeUInt32(input.sequence, out)
  }

  override def validate(input: TxIn): Unit = {
    require(input.signatureScript.length <= MaxScriptElementSize, s"signature script is ${input.signatureScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }

  def coinbase(script: BinaryData): TxIn = {
    require(script.length >= 2 && script.length <= 100, "coinbase script length must be between 2 and 100")
    TxIn(OutPoint(new Array[Byte](32), 0xffffffffL), script, sequence = 0xffffffffL)
  }

  def coinbase(script: Seq[ScriptElt]): TxIn = coinbase(Script.write(script))
}

/**
 * Transaction input
  *
  * @param outPoint Previous output transaction reference
 * @param signatureScript Computational Script for confirming transaction authorization
 * @param sequence Transaction version as defined by the sender. Intended for "replacement" of transactions when
 *                 information is updated before inclusion into a block. Unused for now.
 */
case class TxIn(outPoint: OutPoint, signatureScript: BinaryData, sequence: Long) {
  def isFinal: Boolean = sequence == TxIn.SEQUENCE_FINAL
}

object TxOut extends BtcMessage[TxOut] {
  def apply(amount: Satoshi, publicKeyScript: Seq[ScriptElt]): TxOut = new TxOut(amount, Script.write(publicKeyScript))

  override def read(input: InputStream, protocolVersion: Long): TxOut = TxOut(Satoshi(uint64(input)), script(input))

  override def write(input: TxOut, out: OutputStream, protocolVersion: Long) = {
    writeUInt64(input.amount.amount, out)
    writeScript(input.publicKeyScript, out)
  }

  override def validate(input: TxOut): Unit = {
    import input._
    require(amount.amount >= 0, s"invalid txout amount: $amount")
    require(amount.amount <= MaxMoney, s"invalid txout amount: $amount")
    require(publicKeyScript.length < MaxScriptElementSize, s"public key script is ${publicKeyScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }
}

/**
 * Transaction output
  *
  * @param amount amount in Satoshis
 * @param publicKeyScript Usually contains the public key as a Bitcoin script setting up conditions to claim this output.
 */
case class TxOut(amount: Satoshi, publicKeyScript: BinaryData)

object ScriptWitness extends BtcMessage[ScriptWitness] {
  val empty = ScriptWitness(Seq.empty[BinaryData])

  override def write(t: ScriptWitness, out: OutputStream, protocolVersion: Long): Unit =
    writeCollection[BinaryData](t.stack, (b:BinaryData, o:OutputStream, _: Long) => writeScript(b, o), out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): ScriptWitness =
    ScriptWitness(readCollection[BinaryData](in, (i: InputStream, _:Long) => script(i), None, protocolVersion))
}

/**
  * a script witness is just a stack of data
  * there is one script witness per transaction input
  *
  * @param stack items to be pushed on the stack
  */
case class ScriptWitness(stack: Seq[BinaryData]) {
  def isNull = stack.isEmpty
  def isNotNull = !isNull
}

object Transaction extends BtcMessage[Transaction] {
  val SERIALIZE_TRANSACTION_WITNESS = 0x40000000L

  def serializeTxWitness(version: Long): Boolean = (version & SERIALIZE_TRANSACTION_WITNESS) != 0

  def isNotNull(witness: Seq[ScriptWitness]) = witness.exists(_.isNotNull)

  def isNull(witness: Seq[ScriptWitness]) = !isNotNull(witness)

  def apply(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long) = new Transaction(version, txIn, txOut, lockTime, Seq.fill(txIn.size)(ScriptWitness.empty))

  override def read(input: InputStream, protocolVersion: Long): Transaction = {
    val tx = Transaction(uint32(input), readCollection[TxIn](input, protocolVersion), Seq.empty[TxOut], 0)
    val (flags, tx1) = if (tx.txIn.isEmpty && serializeTxWitness(protocolVersion)) {
      // we just read the 0x00 marker
      val flags = uint8(input)
      val txIn = readCollection[TxIn](input, protocolVersion)
      if (flags == 0 && !txIn.isEmpty) throw new RuntimeException("Extended transaction format unnecessarily used")
      val txOut = readCollection[TxOut](input, protocolVersion)
      (flags, tx.copy(txIn = txIn, txOut = txOut))
    } else (0, tx.copy(txOut = readCollection[TxOut](input, protocolVersion)))

    val tx2 = flags match {
      case 0 => tx1.copy(lockTime = uint32(input))
      case 1 =>
        val witness = new ArrayBuffer[ScriptWitness]()
        for (i <- 0 until tx1.txIn.size) witness += ScriptWitness.read(input, protocolVersion)
        tx1.copy(witness = witness.toSeq, lockTime = uint32(input))
      case _ => throw new RuntimeException(s"Unknown transaction optional data $flags")
    }

    tx2
  }

  override def write(tx: Transaction, out: OutputStream, protocolVersion: Long) = {
    if (serializeTxWitness(protocolVersion) && isNotNull(tx.witness)) {
      writeUInt32(tx.version, out)
      writeUInt8(0x00, out)
      writeUInt8(0x01, out)
      writeCollection(tx.txIn, out, protocolVersion)
      writeCollection(tx.txOut, out, protocolVersion)
      for (i <- 0 until tx.txIn.size) ScriptWitness.write(tx.witness(i), out, protocolVersion)
      writeUInt32(tx.lockTime, out)
    } else {
      writeUInt32(tx.version, out)
      writeCollection(tx.txIn, out, protocolVersion)
      writeCollection(tx.txOut, out, protocolVersion)
      writeUInt32(tx.lockTime, out)
    }
  }

  override def validate(input: Transaction): Unit = {
    require(input.txIn.nonEmpty, "input list cannot be empty")
    require(input.txOut.nonEmpty, "output list cannot be empty")
    require(Transaction.write(input).size <= MaxBlockSize)
    require(input.txOut.map(_.amount.amount).sum <= MaxMoney, "sum of outputs amount is invalid")
    input.txIn.map(TxIn.validate)
    input.txOut.map(TxOut.validate)
    val outPoints = input.txIn.map(_.outPoint)
    require(outPoints.size == outPoints.toSet.size, "duplicate inputs")
    if (Transaction.isCoinbase(input)) {
      require(input.txIn(0).signatureScript.size >= 2, "coinbase script size")
      require(input.txIn(0).signatureScript.size <= 100, "coinbase script size")
    } else {
      require(input.txIn.forall(in => !OutPoint.isCoinbase(in.outPoint)), "prevout is null")
    }
  }

  def isCoinbase(input: Transaction) = input.txIn.size == 1 && OutPoint.isCoinbase(input.txIn(0).outPoint)

  /**
   * prepare a transaction for signing a specific input
    *
    * @param tx input transaction
   * @param inputIndex index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType signature hash type
   * @return a new transaction with proper inputs and outputs according to SIGHASH_TYPE rules
   */
  def prepareForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Array[Byte], sighashType: Int): Transaction = {
    val filteredScript = Script.write(Script.parse(previousOutputScript).filterNot(_ == OP_CODESEPARATOR))

    def removeSignatureScript(txin: TxIn): TxIn = txin.copy(signatureScript = Array.empty[Byte])
    def removeAllSignatureScripts(tx: Transaction): Transaction = tx.copy(txIn = tx.txIn.map(removeSignatureScript))
    def updateSignatureScript(tx: Transaction, index: Int, script: Array[Byte]): Transaction = tx.copy(txIn = tx.txIn.updated(index, tx.txIn(index).copy(signatureScript = script)))
    def resetSequence(txins: Seq[TxIn], inputIndex: Int): Seq[TxIn] = for (i <- 0 until txins.size) yield {
      if (i == inputIndex) txins(i)
      else txins(i).copy(sequence = 0)
    }

    val txCopy = {
      // remove all signature scripts, and replace the sig script for the input that we are processing with the
      // pubkey script of the output that we are trying to claim
      val tx1 = removeAllSignatureScripts(tx)
      val tx2 = updateSignatureScript(tx1, inputIndex, filteredScript)

      val tx3 = if (isHashNone(sighashType)) {
        // hash none: remove all outputs
        val inputs = resetSequence(tx2.txIn, inputIndex)
        tx2.copy(txIn = inputs, txOut = List())
      }
      else if (isHashSingle(sighashType)) {
        // hash single: remove all outputs but the one that we are trying to claim
        val inputs = resetSequence(tx2.txIn, inputIndex)
        val outputs = for (i <- 0 to inputIndex) yield {
          if (i == inputIndex) tx2.txOut(inputIndex)
          else TxOut(Satoshi(-1), Array.empty[Byte])
        }
        tx2.copy(txIn = inputs, txOut = outputs)
      }
      else tx2
      // anyone can pay: remove all inputs but the one that we are processing
      val tx4 = if (isAnyoneCanPay(sighashType)) tx3.copy(txIn = List(tx3.txIn(inputIndex))) else tx3
      tx4
    }
    txCopy
  }

  /**
   * hash a tx for signing
    *
    * @param tx input transaction
   * @param inputIndex index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType signature hash type
   * @return a hash which can be used to sign the referenced tx input
   */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Array[Byte], sighashType: Int): Array[Byte] = {
    if (isHashSingle(sighashType) && inputIndex >= tx.txOut.length) {
      Hash.One
    } else {
      val txCopy = prepareForSigning(tx, inputIndex, previousOutputScript, sighashType)
      Crypto.hash256(Transaction.write(txCopy) ++ writeUInt32(sighashType))
    }
  }

  /**
   *
   * @param tx input transaction
   * @param inputIndex index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType signature hash type, which will be appended to the signature
   * @param privateKey private key
   * @param randomize if false, the output signature will not be randomized (use for testing only)
   * @return the encoded signature of this tx for this specific tx input
   */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: Array[Byte], sighashType: Int, privateKey: Array[Byte], randomize: Boolean = true): Array[Byte] = {
    val hash = hashForSigning(tx, inputIndex, previousOutputScript, sighashType)
    val (r, s) = Crypto.sign(hash, privateKey.take(32), randomize)
    val sig = Crypto.encodeSignature(r, s)
    sig :+ (sighashType.toByte)
  }

  /**
   * Sign a transaction. Cannot partially sign. All the input are signed with SIGHASH_ALL
    *
    * @param input transaction to sign
   * @param signData list of data for signing: previous tx output script and associated private key
   * @param randomize if false, signature will not be randomized. Use for debugging purposes only!
   * @return a new signed transaction
   */
  def sign(input: Transaction, signData: Seq[SignData], randomize: Boolean = true): Transaction = {

    require(signData.length == input.txIn.length, "There should be signing data for every transaction")

    // sign each input
    val signedInputs = for (i <- 0 until input.txIn.length) yield {
      val sig = signInput(input, i, signData(i).prevPubKeyScript, SIGHASH_ALL, signData(i).privateKey, randomize)

      // this is the public key that is associated with the private key we used for signing
      val publicKey = Crypto.publicKeyFromPrivateKey(signData(i).privateKey)

      // signature script: push signature and public key
      val sigScript = Script.write(OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)
      input.txIn(i).copy(signatureScript = sigScript)
    }

    input.copy(txIn = signedInputs)
  }

  /**
   * checks that a transaction correctly spends its inputs (i.e is properly signed)
    *
    * @param tx transaction to be checked
   * @param inputs previous tx that are being spent
   * @param scriptFlags script execution flags
   * @throws RuntimeException if the transaction is not valid (i.e executing input and output scripts does not yield "true")
   */
  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int, callback: Option[Runner.Callback]): Unit = {
    val txMap = inputs.map(t => t.txid -> t).toMap
    val prevoutMap = for (i <- 0 until tx.txIn.length) yield tx.txIn(i).outPoint -> txMap(tx.txIn(i).outPoint.txid).txOut(tx.txIn(i).outPoint.index.toInt).publicKeyScript
    correctlySpends(tx, prevoutMap.toMap, scriptFlags, callback)
  }

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit = correctlySpends(tx, inputs, scriptFlags, None)

    /**
   * checks that a transaction correctly spends its inputs (i.e sis properly signed)
      *
      * @param tx transaction to be checked
   * @param prevoutScripts map where keys are OutPoint (previous tx ids and vout index) and values are previous output pubkey scripts)
   * @param scriptFlags script execution flags
   * @throws RuntimeException if the transaction is not valid (i.e executing input and output scripts does not yield "true")
   */
  def correctlySpends(tx: Transaction, prevoutScripts: Map[OutPoint, BinaryData], scriptFlags: Int, callback: Option[Runner.Callback] = None): Unit = {
    for (i <- 0 until tx.txIn.length if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
      val prevOutputScript = prevoutScripts(tx.txIn(i).outPoint)
      val ctx = new Script.Context(tx, i)
      val runner = new Script.Runner(ctx, scriptFlags, callback)
      if (!runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript)) throw new RuntimeException(s"tx ${tx.txid} does not spend its input # $i")
    }
  }
}

object SignData {
  def apply(prevPubKeyScript: Seq[ScriptElt], privateKey: BinaryData): SignData = new SignData(Script.write(prevPubKeyScript), privateKey)
}

/**
 * data for signing pay2pk transaction
  *
  * @param prevPubKeyScript previous output public key script
 * @param privateKey private key associated with the previous output public key
 */
case class SignData(prevPubKeyScript: BinaryData, privateKey: BinaryData)

/**
 * Transaction
  *
  * @param version Transaction data format version
 * @param txIn Transaction inputs
 * @param txOut Transaction outputs
 * @param lockTime The block number or timestamp at which this transaction is locked
 */
case class Transaction(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long, witness: Seq[ScriptWitness]) {
  lazy val hash: BinaryData = Crypto.hash256(Transaction.write(this))
  lazy val txid = BinaryData(hash.reverse)

  /**
   *
   * @param blockHeight current block height
   * @param blockTime current block time
   * @return true if the transaction is final
   */
  def isFinal(blockHeight: Long, blockTime: Long): Boolean = lockTime match {
    case 0 => true
    case value if value < LockTimeThreshold && value < blockHeight => true
    case value if value >= LockTimeThreshold && value < blockTime => true
    case _ if txIn.exists(!_.isFinal) => false
    case _ => true
  }

  /**
   *
   * @param i index of the tx input to update
   * @param sigScript new signature script
   * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
   */
  def updateSigScript(i: Int, sigScript: BinaryData) : Transaction = this.copy(txIn = txIn.updated(i, txIn(i).copy(signatureScript = sigScript)))

  /**
   *
   * @param i index of the tx input to update
   * @param sigScript new signature script
   * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
   */
  def updateSigScript(i: Int, sigScript: Seq[ScriptElt]) : Transaction = updateSigScript(i, Script.write(sigScript))
}

object BlockHeader extends BtcMessage[BlockHeader] {
  override def read(input: InputStream, protocolVersion: Long): BlockHeader = {
    val version = uint32(input)
    val hashPreviousBlock = hash(input)
    val hashMerkleRoot = hash(input)
    val time = uint32(input)
    val bits = uint32(input)
    val nonce = uint32(input)
    BlockHeader(version, hashPreviousBlock, hashMerkleRoot, time, bits, nonce)
  }

  override def write(input: BlockHeader, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.version, out)
    out.write(input.hashPreviousBlock)
    out.write(input.hashMerkleRoot)
    writeUInt32(input.time, out)
    writeUInt32(input.bits, out)
    writeUInt32(input.nonce, out)
  }

  def getDifficulty(header: BlockHeader): BigInteger = {
    val nsize = header.bits >> 24
    val isneg = header.bits & 0x00800000
    val nword = header.bits & 0x007fffff
    val result = if (nsize <= 3)
      BigInteger.valueOf(nword).shiftRight(8 * (3 - nsize.toInt))
    else
      BigInteger.valueOf(nword).shiftLeft(8 * (nsize.toInt - 3))
    if (isneg != 0) result.negate() else result
  }
}

/**
 *
 * @param version Block version information, based upon the software version creating this block
 * @param hashPreviousBlock The hash value of the previous block this particular block references. Please not that
 *                          this hash is not reversed (as opposed to Block.hash)
 * @param hashMerkleRoot The reference to a Merkle tree collection which is a hash of all transactions related to this block
 * @param time A timestamp recording when this block was created (Will overflow in 2106[2])
 * @param bits The calculated difficulty target being used for this block
 * @param nonce The nonce used to generate this block… to allow variations of the header and compute different hashes
 */
case class BlockHeader(version: Long, hashPreviousBlock: BinaryData, hashMerkleRoot: BinaryData, time: Long, bits: Long, nonce: Long) {
  require(hashPreviousBlock.length == 32, "hashPreviousBlock must be 32 bytes")
  require(hashMerkleRoot.length == 32, "hashMerkleRoot must be 32 bytes")
  lazy val hash: BinaryData = Crypto.hash256(BlockHeader.write(this))
}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
 */
object MerkleTree {
  def computeRoot(tree: Seq[Array[Byte]]): Array[Byte] = tree.length match {
    case 1 => tree(0)
    case n if n % 2 != 0 => computeRoot(tree :+ tree.last) // append last element again
    case _ => computeRoot(tree.grouped(2).map(a => Crypto.hash256(a(0) ++ a(1))).toSeq)
  }
}

object Block extends BtcMessage[Block] {
  override def read(input: InputStream, protocolVersion: Long): Block = {
    val raw = bytes(input, 80)
    val header = BlockHeader.read(raw)
    Block(header, readCollection[Transaction](input, protocolVersion))
  }

  override def write(input: Block, out: OutputStream, protocolVersion: Long) = {
    BlockHeader.write(input.header, out)
    writeCollection(input.tx, out, protocolVersion)
  }

  override def validate(input: Block): Unit = {
    BlockHeader.validate(input.header)
    require(util.Arrays.equals(input.header.hashMerkleRoot, MerkleTree.computeRoot(input.tx.map(_.hash.toArray))), "invalid block:  merkle root mismatch")
    require(input.tx.map(_.txid).toSet.size == input.tx.size, "invalid block: duplicate transactions")
    input.tx.map(Transaction.validate)
  }

  // genesis block
  val LivenetGenesisBlock = {
    val script = OP_PUSHDATA(writeUInt32(486604799L)) :: OP_PUSHDATA(writeUInt8(4)) :: OP_PUSHDATA("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".getBytes("UTF-8")) :: Nil
    val scriptPubKey = OP_PUSHDATA("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") :: OP_CHECKSIG :: Nil
    Block(
      BlockHeader(version = 1, hashPreviousBlock = Hash.Zeroes, hashMerkleRoot = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a", time = 1231006505, bits = 0x1d00ffff, nonce = 2083236893),
      List(
        Transaction(version = 1,
          txIn = List(TxIn.coinbase(script)),
          txOut = List(TxOut(amount = 50 btc, publicKeyScript = scriptPubKey)),
          lockTime = 0))
    )
  }

  // testnet genesis block
  val TestnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458))

  val RegtestGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 0x207fffffL, nonce = 2, time = 1296688602))

  // mine.header.copy(bits = 0x0x207fffffL, nonce = 2, time = 1296688602)
  /**
   * Proof of work: hash(block) <= target difficulty
    *
    * @param block
   * @return true if the input block validates its expected proof of work
   */
  def checkProofOfWork(block: Block): Boolean = {
    val (target, _, _) = decodeCompact(block.header.bits)
    val hash = new BigInteger(1, block.blockId.toArray)
    hash.compareTo(target) <= 0
  }
}

/**
 * Bitcoin block
  *
  * @param header block header
 * @param tx transactions
 */
case class Block(header: BlockHeader, tx: Seq[Transaction]) {
  lazy val hash = header.hash

  // hash is reversed here (same as tx id)
  lazy val blockId = BinaryData(hash.reverse)
}

object Message extends BtcMessage[Message] {
  val MagicMain = 0xD9B4BEF9L
  val MagicTestNet = 0xDAB5BFFAL
  val MagicTestnet3 = 0x0709110BL
  val MagicNamecoin = 0xFEB4BEF9L

  override def read(in: InputStream, protocolVersion: Long): Message = {
    val magic = uint32(in)
    val buffer = new Array[Byte](12)
    in.read(buffer)
    val buffer1 = buffer.takeWhile(_ != 0)
    val command = new String(buffer1, "ISO-8859-1")
    val length = uint32(in)
    require(length < 2000000, "invalid payload length")
    val checksum = uint32(in)
    val payload = new Array[Byte](length.toInt)
    in.read(payload)
    require(checksum == uint32(Crypto.hash256(payload).take(4)), "invalid checksum")
    Message(magic, command, payload)
  }

  override def write(input: Message, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.magic, out)
    val buffer = new Array[Byte](12)
    input.command.getBytes("ISO-8859-1").copyToArray(buffer)
    out.write(buffer)
    writeUInt32(input.payload.length, out)
    val checksum = Crypto.hash256(input.payload).take(4)
    out.write(checksum)
    out.write(input.payload)
  }
}

/**
 * Bitcoin message exchanged by nodes over the network
  *
  * @param magic Magic value indicating message origin network, and used to seek to next message when stream state is unknown
 * @param command ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
 * @param payload The actual data
 */
case class Message(magic: Long, command: String, payload: BinaryData) {
  require(command.length <= 12)
}

object NetworkAddressWithTimestamp extends BtcMessage[NetworkAddressWithTimestamp] {
  override def read(in: InputStream, protocolVersion: Long): NetworkAddressWithTimestamp = {
    val time = uint32(in)
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    val address = InetAddress.getByAddress(raw)
    val port = uint16BigEndian(in)
    NetworkAddressWithTimestamp(time, services, address, port)
  }

  override def write(input: NetworkAddressWithTimestamp, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.time, out)
    writeUInt64(input.services, out)
    input.address match {
      case _: Inet4Address => out.write(fromHexString("00000000000000000000ffff"))
      case _: Inet6Address => ()
    }
    out.write(input.address.getAddress)
    writeUInt16BigEndian(input.port, out)
  }
}

case class NetworkAddressWithTimestamp(time: Long, services: Long, address: InetAddress, port: Long)

object NetworkAddress extends BtcMessage[NetworkAddress] {
  override def read(in: InputStream, protocolVersion: Long): NetworkAddress = {
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    val address = InetAddress.getByAddress(raw)
    val port = uint16BigEndian(in)
    NetworkAddress(services, address, port)
  }

  override def write(input: NetworkAddress, out: OutputStream, protocolVersion: Long) = {
    writeUInt64(input.services, out)
    input.address match {
      case _: Inet4Address => out.write(fromHexString("00000000000000000000ffff"))
      case _: Inet6Address => ()
    }
    out.write(input.address.getAddress)
    writeUInt16BigEndian(input.port, out) // wtf ?? why BE there ?
  }
}

case class NetworkAddress(services: Long, address: InetAddress, port: Long)

object Version extends BtcMessage[Version] {
  override def read(in: InputStream, protocolVersion: Long): Version = {
    val version = uint32(in)
    val services = uint64(in)
    val timestamp = uint64(in)
    val addr_recv = NetworkAddress.read(in)
    val addr_from = NetworkAddress.read(in)
    val nonce = uint64(in)
    val length = varint(in)
    val buffer = new Array[Byte](length.toInt)
    in.read(buffer)
    val user_agent = new String(buffer, "ISO-8859-1")
    val start_height = uint32(in)
    val relay = if (uint8(in) == 0) false else true
    Version(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, start_height, relay)
  }

  override def write(input: Version, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.version, out)
    writeUInt64(input.services, out)
    writeUInt64(input.timestamp, out)
    NetworkAddress.write(input.addr_recv, out)
    NetworkAddress.write(input.addr_from, out)
    writeUInt64(input.nonce, out)
    writeVarint(input.user_agent.length, out)
    out.write(input.user_agent.getBytes("ISO-8859-1"))
    writeUInt32(input.start_height, out)
    writeUInt8(if (input.relay) 1 else 0, out)
  }
}

/**
 *
 * @param version Identifies protocol version being used by the node
 * @param services bitfield of features to be enabled for this connection
 * @param timestamp standard UNIX timestamp in seconds
 * @param addr_recv The network address of the node receiving this message
 * @param addr_from The network address of the node emitting this message
 * @param nonce Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect
 *              connections to self.
 * @param user_agent User Agent
 * @param start_height The last block received by the emitting node
 * @param relay Whether the remote peer should announce relayed transactions or not, see BIP 0037,
 *              since version >= 70001
 */
case class Version(version: Long, services: Long, timestamp: Long, addr_recv: NetworkAddress, addr_from: NetworkAddress, nonce: Long, user_agent: String, start_height: Long, relay: Boolean)

object Addr extends BtcMessage[Addr] {
  override def write(t: Addr, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.addresses, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Addr =
    Addr(readCollection[NetworkAddressWithTimestamp](in, Some(1000), protocolVersion))
}

case class Addr(addresses: Seq[NetworkAddressWithTimestamp])

object InventoryVector extends BtcMessage[InventoryVector] {
  val ERROR = 0L
  val MSG_TX = 1L
  val MSG_BLOCK = 2L

  override def write(t: InventoryVector, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.`type`, out)
    out.write(t.hash)
  }

  override def read(in: InputStream, protocolVersion: Long): InventoryVector = InventoryVector(uint32(in), hash(in))
}

case class InventoryVector(`type`: Long, hash: BinaryData) {
  require(hash.length == 32, "invalid hash length")
}

object Inventory extends BtcMessage[Inventory] {
  override def write(t: Inventory, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.inventory, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Inventory = Inventory(readCollection[InventoryVector](in, Some(1000), protocolVersion))
}

case class Inventory(inventory: Seq[InventoryVector])

object Getheaders extends BtcMessage[Getheaders] {
  override def write(t: Getheaders, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.version, out)
    writeCollection(t.locatorHashes, (h:BinaryData, o:OutputStream, _: Long) => o.write(h), out, protocolVersion)
    out.write(t.stopHash)
  }

  override def read(in: InputStream, protocolVersion: Long): Getheaders = {
    Getheaders(version = uint32(in), locatorHashes = readCollection[BinaryData](in, (i: InputStream, _: Long) => BinaryData(hash(i)), protocolVersion), stopHash = hash(in))
  }
}

case class Getheaders(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) {
  locatorHashes.map(h => require(h.length == 32))
  require(stopHash.length == 32)
}

object Headers extends BtcMessage[Headers] {
  override def write(t: Headers, out: OutputStream, protocolVersion: Long): Unit = {
    writeCollection(t.headers, (t:BlockHeader, o:OutputStream, v: Long) => {
      BlockHeader.write(t, o, v)
      writeVarint(0, o)
    }, out, protocolVersion)
  }

  override def read(in: InputStream, protocolVersion: Long): Headers = {
    Headers(readCollection(in, (i: InputStream, v: Long) => {
      val header = BlockHeader.read(i, v)
      val dummy = varint(in)
      require(dummy == 0, s"header in headers message ends with $dummy, should be 0 instead")
      header
    }, protocolVersion))
  }
}

case class Headers(headers: Seq[BlockHeader])

object Getblocks extends BtcMessage[Getblocks] {
  override def write(t: Getblocks, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt32(t.version, out)
    writeCollection(t.locatorHashes, (h: BinaryData, o:OutputStream, _: Long) => o.write(h), out, protocolVersion)
    out.write(t.stopHash)
  }

  override def read(in: InputStream, protocolVersion: Long): Getblocks = {
    Getblocks(version =  uint32(in), locatorHashes = readCollection(in, (i: InputStream, _: Long) => BinaryData(hash(i)), protocolVersion), stopHash = hash(in))
  }
}

case class Getblocks(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) {
  locatorHashes.map(h => require(h.length == 32))
  require(stopHash.length == 32)
}

object Getdata extends BtcMessage[Getdata] {
  override def write(t: Getdata, out: OutputStream, protocolVersion: Long): Unit = writeCollection(t.inventory, out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): Getdata = Getdata(readCollection[InventoryVector](in, protocolVersion))
}

case class Getdata(inventory: Seq[InventoryVector])

object Reject extends BtcMessage[Reject] {
  override def write(t: Reject, out: OutputStream, protocolVersion: Long): Unit = {
    writeVarstring(t.message, out)
    writeUInt8(t.code, out)
    writeVarstring(t.reason, out)
  }

  override def read(in: InputStream, protocolVersion: Long): Reject = {
    Reject(message = varstring(in), code = uint8(in), reason =  varstring(in), Array.empty[Byte])
  }
}

case class Reject(message: String, code: Long, reason: String, data: BinaryData)