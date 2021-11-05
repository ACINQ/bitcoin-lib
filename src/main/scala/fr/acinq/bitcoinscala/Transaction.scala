package fr.acinq.bitcoinscala

import fr.acinq.bitcoin
import fr.acinq.bitcoinscala.Crypto.PrivateKey
import fr.acinq.bitcoinscala.KotlinUtils._
import fr.acinq.bitcoinscala.Protocol._
import scodec.bits.ByteVector

import java.io.{InputStream, OutputStream}
import scala.jdk.CollectionConverters.MapHasAsJava

object OutPoint extends BtcSerializer[OutPoint] {
  def apply(tx: Transaction, index: Int) = new OutPoint(ByteVector32(tx.hash), index)

  override def read(input: InputStream, protocolVersion: Long): OutPoint = OutPoint(hash(input), uint32(input))

  override def write(input: OutPoint, out: OutputStream, protocolVersion: Long): Unit = {
    out.write(input.hash.toArray)
    writeUInt32(input.index.toInt, out)
  }

  def isCoinbase(input: OutPoint) = input.index == 0xffffffffL && input.hash == ByteVector32.Zeroes

  def isNull(input: OutPoint) = isCoinbase(input)
}

/**
 * an out point is a reference to a specific output in a specific transaction that we want to claim
 *
 * @param hash  reversed sha256(sha256(tx)) where tx is the transaction we want to refer to
 * @param index index of the output in tx that we want to refer to
 */
case class OutPoint(hash: ByteVector32, index: Long) extends BtcSerializable[OutPoint] {
  // The genesis block contains inputs with index = -1, so we cannot require it to be >= 0
  require(index >= -1)

  /**
   *
   * @return the id of the transaction this output belongs to
   */
  val txid: ByteVector32 = hash.reverse

  override def serializer: BtcSerializer[OutPoint] = OutPoint
}

object TxIn extends BtcSerializer[TxIn] {
  def apply(outPoint: OutPoint, signatureScript: Seq[ScriptElt], sequence: Long): TxIn = new TxIn(outPoint, Script.write(signatureScript), sequence)

  override def read(input: InputStream, protocolVersion: Long): TxIn = TxIn(outPoint = OutPoint.read(input), signatureScript = script(input), sequence = uint32(input))

  override def write(input: TxIn, out: OutputStream, protocolVersion: Long): Unit = {
    OutPoint.write(input.outPoint, out)
    writeScript(input.signatureScript.toArray, out)
    writeUInt32(input.sequence.toInt, out)
  }

  override def validate(input: TxIn): Unit = {
    require(input.signatureScript.length <= bitcoin.Script.MaxScriptElementSize, s"signature script is ${input.signatureScript.length} bytes, limit is ${bitcoin.Script.MaxScriptElementSize} bytes")
  }

  def coinbase(script: ByteVector): TxIn = {
    require(script.length >= 2 && script.length <= 100, "coinbase script length must be between 2 and 100")
    TxIn(OutPoint(ByteVector32.Zeroes, 0xffffffffL), script, sequence = 0xffffffffL)
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
case class TxIn(outPoint: OutPoint, signatureScript: ByteVector, sequence: Long, witness: ScriptWitness = ScriptWitness.empty) extends BtcSerializable[TxIn] {
  def isFinal: Boolean = sequence == bitcoin.TxIn.SEQUENCE_FINAL

  def hasWitness: Boolean = witness.isNotNull

  override def serializer: BtcSerializer[TxIn] = TxIn
}

object TxOut extends BtcSerializer[TxOut] {
  def apply(amount: Satoshi, publicKeyScript: Seq[ScriptElt]): TxOut = new TxOut(amount, Script.write(publicKeyScript))

  override def read(input: InputStream, protocolVersion: Long): TxOut = TxOut(Satoshi(uint64(input)), script(input))

  override def write(input: TxOut, out: OutputStream, protocolVersion: Long): Unit = {
    writeUInt64(input.amount.toLong, out)
    writeScript(input.publicKeyScript.toArray, out)
  }

  override def validate(input: TxOut): Unit = {
    import input._
    require(amount.toLong >= 0, s"invalid txout amount: $amount")
    require(amount.toLong <= BtcAmount.MaxMoney, s"invalid txout amount: $amount")
    require(publicKeyScript.length < bitcoin.Script.MaxScriptElementSize, s"public key script is ${publicKeyScript.length} bytes, limit is ${bitcoin.Script.MaxScriptElementSize} bytes")
  }
}

/**
 * Transaction output
 *
 * @param amount          amount in Satoshis
 * @param publicKeyScript public key script which sets the conditions for spending this output
 */
case class TxOut(amount: Satoshi, publicKeyScript: ByteVector) extends BtcSerializable[TxOut] {
  override def serializer: BtcSerializer[TxOut] = TxOut
}

object ScriptWitness extends BtcSerializer[ScriptWitness] {
  val empty = ScriptWitness(Seq.empty[ByteVector])

  override def write(t: ScriptWitness, out: OutputStream, protocolVersion: Long): Unit =
    writeCollection[ByteVector](t.stack, (b: ByteVector, o: OutputStream, _: Long) => writeScript(b.toArray, o), out, protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): ScriptWitness =
    ScriptWitness(readCollection[ByteVector](in, (i: InputStream, _: Long) => script(i), None, protocolVersion))
}

/**
 * a script witness is just a stack of data
 * there is one script witness per transaction input
 *
 * @param stack items to be pushed on the stack
 */
case class ScriptWitness(stack: Seq[ByteVector]) extends BtcSerializable[ScriptWitness] {
  def isNull = stack.isEmpty

  def isNotNull = !isNull

  override def serializer: BtcSerializer[ScriptWitness] = ScriptWitness
}

object Transaction extends BtcSerializer[Transaction] {
  /**
   *
   * @param version protocol version (and NOT transaction version !)
   * @return true if protocol version specifies that witness data is to be serialized
   */
  def serializeTxWitness(version: Long): Boolean = (version & bitcoin.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS) == 0

  override def read(input: InputStream, protocolVersion: Long): Transaction = {
    val tx = fr.acinq.bitcoin.Transaction.read(InputStreamWrapper(input), protocolVersion)
    tx
  }

  override def write(tx: Transaction, out: OutputStream, protocolVersion: Long): Unit = {
    fr.acinq.bitcoin.Transaction.write(tx, OutputStreamWrapper(out), protocolVersion)
  }

  override def validate(input: Transaction): Unit = {
    fr.acinq.bitcoin.Transaction.validate(input)
  }

  def baseSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion | bitcoin.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS).length.toInt

  def totalSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion).length.toInt

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
  def prepareForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int): Transaction = {
    fr.acinq.bitcoin.Transaction.prepareForSigning(tx, inputIndex, previousOutputScript.toArray, sighashType)
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
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int): ByteVector32 = {
    ByteVector32(ByteVector.view(fr.acinq.bitcoin.Transaction.hashForSigning(tx, inputIndex, previousOutputScript.toArray, sighashType)))
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
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int): ByteVector32 =
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
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int, amount: Satoshi, signatureVersion: Int): ByteVector32 = {
    ByteVector32(ByteVector.view(fr.acinq.bitcoin.Transaction.hashForSigning(tx, inputIndex, previousOutputScript.toArray, sighashType, amount, signatureVersion)))
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
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int): ByteVector32 =
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
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): ByteVector = {
    ByteVector.view(fr.acinq.bitcoin.Transaction.signInput(tx, inputIndex, scala2kmp(previousOutputScript), sighashType, amount, signatureVersion, privateKey.priv))
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
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): ByteVector =
    signInput(tx, inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion, privateKey)

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int): Unit = {
    fr.acinq.bitcoin.Transaction.correctlySpends(tx, previousOutputs.map { case (o, t) => scala2kmp(o) -> scala2kmp(t) }.asJava, scriptFlags)
  }

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit = {
    val prevouts = tx.txIn.map(_.outPoint).map(outpoint => {
      val prevTx = inputs.find(_.txid == outpoint.txid).get
      val prevOutput = prevTx.txOut(outpoint.index.toInt)
      outpoint -> prevOutput
    }).toMap
    correctlySpends(tx, prevouts, scriptFlags)
  }
}

/**
 * Transaction
 *
 * @param version  Transaction data format version
 * @param txIn     Transaction inputs
 * @param txOut    Transaction outputs
 * @param lockTime The block number or timestamp at which this transaction is locked
 */
case class Transaction(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long) extends BtcSerializable[Transaction] {

  // standard transaction hash, used to identify transactions (in transactions outputs for example)
  lazy val hash: ByteVector32 = Crypto.hash256(Transaction.write(this, bitcoin.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS))
  lazy val txid: ByteVector32 = hash.reverse
  // witness transaction hash that includes witness data. used to compute the witness commitment included in the coinbase
  // transaction of segwit blocks
  lazy val whash: ByteVector32 = Crypto.hash256(Transaction.write(this))
  lazy val wtxid: ByteVector32 = whash.reverse
  lazy val bin: ByteVector = Transaction.write(this)

  // this is much easier to use than Scala's default toString
  override def toString: String = bin.toHex

  /**
   *
   * @param blockHeight current block height
   * @param blockTime   current block time
   * @return true if the transaction is final
   */
  def isFinal(blockHeight: Long, blockTime: Long): Boolean = lockTime match {
    case 0 => true
    case value if value < bitcoin.Transaction.LOCKTIME_THRESHOLD && value < blockHeight => true
    case value if value >= bitcoin.Transaction.LOCKTIME_THRESHOLD && value < blockTime => true
    case _ if txIn.exists(!_.isFinal) => false
    case _ => true
  }

  /**
   *
   * @param i         index of the tx input to update
   * @param sigScript new signature script
   * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
   */
  def updateSigScript(i: Int, sigScript: ByteVector): Transaction = this.copy(txIn = txIn.updated(i, txIn(i).copy(signatureScript = sigScript)))

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
