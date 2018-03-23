package fr.acinq.bitcoin

import java.io.{ByteArrayOutputStream, InputStream, OutputStream}

import fr.acinq.bitcoin.Crypto.PrivateKey
import fr.acinq.bitcoin.Protocol._
import fr.acinq.bitcoin.Script.Runner

import scala.collection.mutable.ArrayBuffer

object OutPoint extends BtcSerializer[OutPoint] {
  def apply(tx: Transaction, index: Int) = new OutPoint(tx.hash, index)

  override def read(input: InputStream, protocolVersion: Long): OutPoint = OutPoint(hash(input), uint32(input))

  override def write(input: OutPoint, out: OutputStream, protocolVersion: Long) = {
    out.write(input.hash)
    writeUInt32(input.index.toInt, out)
  }

  def isCoinbase(input: OutPoint) = input.index == 0xffffffffL && input.hash == Hash.Zeroes

  def isNull(input: OutPoint) = isCoinbase(input)

}

/**
  * an out point is a reference to a specific output in a specific transaction that we want to claim
  *
  * @param hash  reversed sha256(sha256(tx)) where tx is the transaction we want to refer to
  * @param index index of the output in tx that we want to refer to
  */
case class OutPoint(hash: BinaryData, index: Long) extends BtcSerializable[OutPoint] {
  require(hash.length == 32)
  require(index >= -1)

  /**
    *
    * @return the id of the transaction this output belongs to
    */
  val txid: BinaryData = hash.data.reverse

  override def serializer: BtcSerializer[OutPoint] = OutPoint
}

object TxIn extends BtcSerializer[TxIn] {
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
    writeUInt32(input.sequence.toInt, out)
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
  * @param outPoint        Previous output transaction reference
  * @param signatureScript Signature script which should match the public key script of the output that we want to spend
  * @param sequence        Transaction version as defined by the sender. Intended for "replacement" of transactions when
  *                        information is updated before inclusion into a block. Repurposed for OP_CSV (see BIPs 68 & 112)
  * @param witness         Transaction witness (i.e. what is in sig script for standard transactions).
  */
case class TxIn(outPoint: OutPoint, signatureScript: BinaryData, sequence: Long, witness: ScriptWitness = ScriptWitness.empty) extends BtcSerializable[TxIn] {
  def isFinal: Boolean = sequence == TxIn.SEQUENCE_FINAL

  def hasWitness: Boolean = witness.isNotNull

  override def serializer: BtcSerializer[TxIn] = TxIn
}

object TxOut extends BtcSerializer[TxOut] {
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
  * @param amount          amount in Satoshis
  * @param publicKeyScript public key script which sets the conditions for spending this output
  */
case class TxOut(amount: Satoshi, publicKeyScript: BinaryData) extends BtcSerializable[TxOut] {
  override def serializer: BtcSerializer[TxOut] = TxOut
}

object ScriptWitness extends BtcSerializer[ScriptWitness] {
  val empty = ScriptWitness(Seq.empty[BinaryData])

  override def write(t: ScriptWitness, out: OutputStream, protocolVersion: Long): Unit =
    writeCollection[BinaryData](t.stack, (b: BinaryData, o: OutputStream, _: Long) => writeScript(b, o), out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): ScriptWitness =
    ScriptWitness(readCollection[BinaryData](in, (i: InputStream, _: Long) => script(i), None, protocolVersion))
}

/**
  * a script witness is just a stack of data
  * there is one script witness per transaction input
  *
  * @param stack items to be pushed on the stack
  */
case class ScriptWitness(stack: Seq[BinaryData]) extends BtcSerializable[ScriptWitness] {
  def isNull = stack.isEmpty

  def isNotNull = !isNull

  override def serializer: BtcSerializer[ScriptWitness] = ScriptWitness
}

object Transaction extends BtcSerializer[Transaction] {
  val SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000L
  // if lockTime >= LOCKTIME_THRESHOLD it is a unix timestamp otherwise it is a block height
  val LOCKTIME_THRESHOLD = 500000000L

  /**
    *
    * @param version protocol version (and NOT transaction version !)
    * @return true if protocol version specifies that witness data is to be serialized
    */
  def serializeTxWitness(version: Long): Boolean = (version & SERIALIZE_TRANSACTION_NO_WITNESS) == 0

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
        val witnesses = new ArrayBuffer[ScriptWitness]()
        for (i <- 0 until tx1.txIn.size) witnesses += ScriptWitness.read(input, protocolVersion)
        tx1.updateWitnesses(witnesses).copy(lockTime = uint32(input))
      case _ => throw new RuntimeException(s"Unknown transaction optional data $flags")
    }

    tx2
  }

  override def write(tx: Transaction, out: OutputStream, protocolVersion: Long) = {
    if (serializeTxWitness(protocolVersion) && tx.hasWitness) {
      writeUInt32(tx.version.toInt, out)
      writeUInt8(0x00, out)
      writeUInt8(0x01, out)
      writeCollection(tx.txIn, out, protocolVersion)
      writeCollection(tx.txOut, out, protocolVersion)
      for (i <- 0 until tx.txIn.size) ScriptWitness.write(tx.txIn(i).witness, out, protocolVersion)
      writeUInt32(tx.lockTime.toInt, out)
    } else {
      writeUInt32(tx.version.toInt, out)
      writeCollection(tx.txIn, out, protocolVersion)
      writeCollection(tx.txOut, out, protocolVersion)
      writeUInt32(tx.lockTime.toInt, out)
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

  def baseSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion | SERIALIZE_TRANSACTION_NO_WITNESS).length

  def totalSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion).length

  def weight(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = totalSize(tx, protocolVersion) + 3 * baseSize(tx, protocolVersion)

  def isCoinbase(input: Transaction) = input.txIn.size == 1 && OutPoint.isCoinbase(input.txIn(0).outPoint)

  /**
    * prepare a transaction for signing a specific input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a new transaction with proper inputs and outputs according to SIGHASH_TYPE rules
    */
  def prepareForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int): Transaction = {
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
    * hash a tx for signing (pre-segwit)
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int): Seq[Byte] = {
    if (isHashSingle(sighashType) && inputIndex >= tx.txOut.length) {
      Hash.One
    } else {
      val txCopy = prepareForSigning(tx, inputIndex, previousOutputScript, sighashType)
      Crypto.hash256(Transaction.write(txCopy, Transaction.SERIALIZE_TRANSACTION_NO_WITNESS) ++ writeUInt32(sighashType))
    }
  }

  /**
    * hash a tx for signing (pre-segwit)
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int): Seq[Byte] =
    hashForSigning(tx, inputIndex, Script.write(previousOutputScript), sighashType)

  /**
    * hash a tx for signing
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @param amount               amount of the output claimed by this input
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int, amount: Satoshi, signatureVersion: Int): Seq[Byte] = {
    signatureVersion match {
      case SigVersion.SIGVERSION_WITNESS_V0 =>
        val hashPrevOut: BinaryData = if (!isAnyoneCanPay(sighashType)) {
          Crypto.hash256(tx.txIn.map(_.outPoint).map(OutPoint.write(_, Protocol.PROTOCOL_VERSION)).flatten)
        } else Hash.Zeroes

        val hashSequence: BinaryData = if (!isAnyoneCanPay(sighashType) && !isHashSingle(sighashType) && !isHashNone(sighashType)) {
          Crypto.hash256(tx.txIn.map(_.sequence).map(s => Protocol.writeUInt32(s.toInt)).flatten)
        } else Hash.Zeroes

        val hashOutputs: BinaryData = if (!isHashSingle(sighashType) && !isHashNone(sighashType)) {
          Crypto.hash256(tx.txOut.map(TxOut.write(_, Protocol.PROTOCOL_VERSION)).flatten)
        } else if (isHashSingle(sighashType) && inputIndex < tx.txOut.size) {
          Crypto.hash256(TxOut.write(tx.txOut(inputIndex), Protocol.PROTOCOL_VERSION))
        } else Hash.Zeroes

        val out = new ByteArrayOutputStream()
        Protocol.writeUInt32(tx.version.toInt, out)
        out.write(hashPrevOut)
        out.write(hashSequence)
        out.write(OutPoint.write(tx.txIn(inputIndex).outPoint, Protocol.PROTOCOL_VERSION))
        Protocol.writeScript(previousOutputScript, out)
        Protocol.writeUInt64(amount.toLong, out)
        Protocol.writeUInt32(tx.txIn(inputIndex).sequence.toInt, out)
        out.write(hashOutputs)
        Protocol.writeUInt32(tx.lockTime.toInt, out)
        Protocol.writeUInt32(sighashType, out)
        val preimage: BinaryData = out.toByteArray
        Crypto.hash256(preimage)
      case _ =>
        hashForSigning(tx, inputIndex, previousOutputScript, sighashType)
    }
  }

  /**
    * hash a tx for signing
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @param amount               amount of the output claimed by this input
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int): Seq[Byte] =
    hashForSigning(tx, inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion)

  /**
    * sign a tx input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type, which will be appended to the signature
    * @param amount               amount of the output claimed by this tx input
    * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
    * @param privateKey           private key
    * @return the encoded signature of this tx for this specific tx input
    */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): BinaryData = {
    if (signatureVersion == SigVersion.SIGVERSION_WITNESS_V0) require(privateKey.compressed, "private key must be compressed in segwit")
    val hash = hashForSigning(tx, inputIndex, previousOutputScript, sighashType, amount, signatureVersion)
    val (r, s) = Crypto.sign(hash, privateKey)
    val sig = Crypto.encodeSignature(r, s)
    sig :+ (sighashType.toByte)
  }

  /**
    * sign a tx input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type, which will be appended to the signature
    * @param amount               amount of the output claimed by this tx input
    * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
    * @param privateKey           private key
    * @return the encoded signature of this tx for this specific tx input
    */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): BinaryData =
    signInput(tx, inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion, privateKey)

  /**
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type, which will be appended to the signature
    * @param privateKey           private key
    * @return the encoded signature of this tx for this specific tx input
    */
  @deprecated("", since = "0.9.6")
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int, privateKey: PrivateKey): BinaryData =
  signInput(tx, inputIndex, previousOutputScript, sighashType, amount = 0 satoshi, signatureVersion = SigVersion.SIGVERSION_BASE, privateKey)

  /**
    * Sign a transaction. Cannot partially sign. All the input are signed with SIGHASH_ALL
    *
    * @param input    transaction to sign
    * @param signData list of data for signing: previous tx output script and associated private key
    * @return a new signed transaction
    */
  def sign(input: Transaction, signData: Seq[SignData]): Transaction = {

    require(signData.length == input.txIn.length, "There should be signing data for every transaction")

    // sign each input
    val signedInputs = for (i <- 0 until input.txIn.length) yield {
      val sig = signInput(input, i, signData(i).prevPubKeyScript, SIGHASH_ALL, 0 satoshi, SigVersion.SIGVERSION_BASE, signData(i).privateKey)

      // this is the public key that is associated with the private key we used for signing
      val publicKey = signData(i).privateKey.publicKey

      // signature script: push signature and public key
      val sigScript = Script.write(OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)
      input.txIn(i).copy(signatureScript = sigScript)
    }

    input.copy(txIn = signedInputs)
  }

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int, callback: Option[Runner.Callback]): Unit = {
    for (i <- 0 until tx.txIn.length if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
      val prevOutput = previousOutputs(tx.txIn(i).outPoint)
      val prevOutputScript = prevOutput.publicKeyScript
      val amount = prevOutput.amount
      val ctx = new Script.Context(tx, i, amount)
      val runner = new Script.Runner(ctx, scriptFlags, callback)
      if (!runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript, tx.txIn(i).witness)) throw new RuntimeException(s"tx ${tx.txid} does not spend its input # $i")
    }
  }

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int): Unit =
    correctlySpends(tx, previousOutputs, scriptFlags, None)

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int, callback: Option[Runner.Callback]): Unit = {
    val prevouts = tx.txIn.map(_.outPoint).map(outpoint => {
      val prevTx = inputs.find(_.txid == outpoint.txid).get
      val prevOutput = prevTx.txOut(outpoint.index.toInt)
      outpoint -> prevOutput
    }).toMap
    correctlySpends(tx, prevouts, scriptFlags, callback)
  }

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit =
    correctlySpends(tx, inputs, scriptFlags, None)
}

object SignData {
  def apply(prevPubKeyScript: Seq[ScriptElt], privateKey: PrivateKey): SignData = new SignData(Script.write(prevPubKeyScript), privateKey)
}

/**
  * data for signing pay2pk transaction
  *
  * @param prevPubKeyScript previous output public key script
  * @param privateKey       private key associated with the previous output public key
  */
case class SignData(prevPubKeyScript: BinaryData, privateKey: PrivateKey)

/**
  * Transaction
  *
  * @param version  Transaction data format version
  * @param txIn     Transaction inputs
  * @param txOut    Transaction outputs
  * @param lockTime The block number or timestamp at which this transaction is locked
  */
case class Transaction(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long) extends BtcSerializable[Transaction] {

  import Transaction._

  // standard transaction hash, used to identify transactions (in transactions outputs for example)
  lazy val hash: BinaryData = Crypto.hash256(Transaction.write(this, SERIALIZE_TRANSACTION_NO_WITNESS))
  lazy val txid: BinaryData = hash.reverse
  // witness transaction hash that includes witness data. used to compute the witness commitment included in the coinbase
  // transaction of segwit blocks
  lazy val whash: BinaryData = Crypto.hash256(Transaction.write(this))
  lazy val wtxid: BinaryData = whash.reverse
  lazy val bin: BinaryData = Transaction.write(this)

  // this is much easier to use than Scala's default toString
  override def toString: String = bin.toString

  /**
    *
    * @param blockHeight current block height
    * @param blockTime   current block time
    * @return true if the transaction is final
    */
  def isFinal(blockHeight: Long, blockTime: Long): Boolean = lockTime match {
    case 0 => true
    case value if value < LOCKTIME_THRESHOLD && value < blockHeight => true
    case value if value >= LOCKTIME_THRESHOLD && value < blockTime => true
    case _ if txIn.exists(!_.isFinal) => false
    case _ => true
  }

  /**
    *
    * @param i         index of the tx input to update
    * @param sigScript new signature script
    * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
    */
  def updateSigScript(i: Int, sigScript: BinaryData): Transaction = this.copy(txIn = txIn.updated(i, txIn(i).copy(signatureScript = sigScript)))

  /**
    *
    * @param i         index of the tx input to update
    * @param sigScript new signature script
    * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
    */
  def updateSigScript(i: Int, sigScript: Seq[ScriptElt]): Transaction = updateSigScript(i, Script.write(sigScript))

  def updateWitness(i: Int, witness: ScriptWitness): Transaction = this.copy(txIn = txIn.updated(i, txIn(i).copy(witness = witness)))

  def updateWitnesses(witnesses: Seq[ScriptWitness]): Transaction = {
    require(witnesses.length == txIn.length)
    witnesses.zipWithIndex.foldLeft(this) {
      case (tx, (witness, index)) => tx.updateWitness(index, witness)
    }
  }

  def hasWitness: Boolean = txIn.exists(_.hasWitness)

  /**
    *
    * @param input input to add the tx
    * @return a new transaction which includes the newly added input
    */
  def addInput(input: TxIn): Transaction = this.copy(txIn = this.txIn :+ input)

  /**
    *
    * @param output output to add to the tx
    * @return a new transaction which includes the newly added output
    */
  def addOutput(output: TxOut): Transaction = this.copy(txOut = this.txOut :+ output)

  def baseSize(protocolVersion: Long = PROTOCOL_VERSION): Int = Transaction.baseSize(this, protocolVersion)

  def totalSize(protocolVersion: Long = PROTOCOL_VERSION): Int = Transaction.totalSize(this, protocolVersion)

  def weight(protocolVersion: Long = PROTOCOL_VERSION): Int = Transaction.weight(this, protocolVersion)

  override def serializer: BtcSerializer[Transaction] = Transaction
}
