package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import fr.acinq.bitcoin.scalacompat.KotlinUtils._
import fr.acinq.bitcoin.scalacompat.Protocol._
import scodec.bits.ByteVector

import java.io.{InputStream, OutputStream}
import scala.jdk.CollectionConverters.{MapHasAsJava, SeqHasAsJava}

/**
 * This is the double hash of a transaction serialized without witness data.
 * Note that this is confusingly called `txid` in some context (e.g. in lightning messages).
 */
case class TxHash(value: ByteVector32) {
  override def toString = value.toString
}

object TxHash {
  def apply(txid: TxId): TxHash = TxHash(txid.value.reverse)

  def fromValidHex(hash: String): TxHash = TxHash(ByteVector32.fromValidHex(hash))
}

/**
 * This contains the same data as [[TxHash]], but encoded with the opposite endianness.
 * Some explorers and bitcoin RPCs use this encoding for their inputs.
 */
case class TxId(value: ByteVector32) {
  override def toString = value.toString
}

object TxId {
  def apply(hash: TxHash): TxId = TxId(hash.value.reverse)

  def fromValidHex(txid: String): TxId = TxId(ByteVector32.fromValidHex(txid))
}

object OutPoint extends BtcSerializer[OutPoint] {
  def apply(tx: Transaction, index: Long): OutPoint = OutPoint(tx.hash, index)

  def apply(txid: TxId, index: Long): OutPoint = OutPoint(TxHash(txid), index)

  override def read(input: InputStream, protocolVersion: Long): OutPoint = kmp2scala(fr.acinq.bitcoin.OutPoint.read(InputStreamWrapper(input), protocolVersion))

  override def write(input: OutPoint, out: OutputStream, protocolVersion: Long): Unit = fr.acinq.bitcoin.OutPoint.write(scala2kmp(input), OutputStreamWrapper(out), protocolVersion)

  def isCoinbase(input: OutPoint): Boolean = scala2kmp(input).isCoinbase

  def isNull(input: OutPoint): Boolean = isCoinbase(input)
}

/**
 * An OutPoint is a reference to a specific output in a specific transaction.
 *
 * @param hash  sha256(sha256(tx)) where tx is the transaction we want to refer to.
 * @param index index of the output in tx that we want to refer to.
 */
case class OutPoint(hash: TxHash, index: Long) extends BtcSerializable[OutPoint] {
  // The genesis block contains inputs with index = -1, so we cannot require it to be >= 0
  require(index >= -1)

  val txid: TxId = TxId(hash)

  override def toString = s"$txid:$index"

  override def serializer: BtcSerializer[OutPoint] = OutPoint
}

object TxIn extends BtcSerializer[TxIn] {
  def apply(outPoint: OutPoint, signatureScript: Seq[ScriptElt], sequence: Long): TxIn = new TxIn(outPoint, Script.write(signatureScript), sequence)

  override def read(input: InputStream, protocolVersion: Long): TxIn = kmp2scala(fr.acinq.bitcoin.TxIn.read(InputStreamWrapper(input), protocolVersion))

  override def write(input: TxIn, out: OutputStream, protocolVersion: Long): Unit = fr.acinq.bitcoin.TxIn.write(scala2kmp(input), OutputStreamWrapper(out), protocolVersion)

  override def validate(input: TxIn): Unit = {
    require(input.signatureScript.length <= bitcoin.Script.MAX_SCRIPT_ELEMENT_SIZE, s"signature script is ${input.signatureScript.length} bytes, limit is ${bitcoin.Script.MAX_SCRIPT_ELEMENT_SIZE} bytes")
  }

  def coinbase(script: ByteVector): TxIn = {
    require(script.length >= 2 && script.length <= 100, "coinbase script length must be between 2 and 100")
    TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0xffffffffL), script, sequence = 0xffffffffL)
  }

  def coinbase(script: Seq[ScriptElt]): TxIn = coinbase(Script.write(script))

  val SEQUENCE_FINAL: Long = fr.acinq.bitcoin.TxIn.SEQUENCE_FINAL
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

  override def read(input: InputStream, protocolVersion: Long): TxOut = kmp2scala(fr.acinq.bitcoin.TxOut.read(InputStreamWrapper(input), protocolVersion))

  override def write(input: TxOut, out: OutputStream, protocolVersion: Long): Unit = fr.acinq.bitcoin.TxOut.write(scala2kmp(input), OutputStreamWrapper(out), protocolVersion)

  override def validate(input: TxOut): Unit = {
    import input._
    require(amount.toLong >= 0, s"invalid txout amount: $amount")
    require(amount.toLong <= BtcAmount.MaxMoney, s"invalid txout amount: $amount")
    require(publicKeyScript.length < bitcoin.Script.MAX_SCRIPT_ELEMENT_SIZE, s"public key script is ${publicKeyScript.length} bytes, limit is ${bitcoin.Script.MAX_SCRIPT_ELEMENT_SIZE} bytes")
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
  val empty: ScriptWitness = ScriptWitness(Seq.empty[ByteVector])

  override def write(t: ScriptWitness, out: OutputStream, protocolVersion: Long): Unit = fr.acinq.bitcoin.ScriptWitness.write(scala2kmp(t), OutputStreamWrapper(out), protocolVersion)

  override def read(in: InputStream, protocolVersion: Long): ScriptWitness = kmp2scala(fr.acinq.bitcoin.ScriptWitness.read(InputStreamWrapper(in), protocolVersion))
}

/**
 * a script witness is just a stack of data
 * there is one script witness per transaction input
 *
 * @param stack items to be pushed on the stack
 */
case class ScriptWitness(stack: Seq[ByteVector]) extends BtcSerializable[ScriptWitness] {
  def isNull: Boolean = stack.isEmpty

  def isNotNull: Boolean = !isNull

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

  def baseSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = fr.acinq.bitcoin.Transaction.baseSize(scala2kmp(tx), protocolVersion)

  def totalSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = fr.acinq.bitcoin.Transaction.totalSize(scala2kmp(tx), protocolVersion)

  def weight(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = totalSize(tx, protocolVersion) + 3 * baseSize(tx, protocolVersion)

  def isCoinbase(input: Transaction): Boolean = input.txIn.size == 1 && OutPoint.isCoinbase(input.txIn.head.outPoint)

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
    tx.prepareForSigning(inputIndex, previousOutputScript, sighashType)
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
    tx.hashForSigning(inputIndex, previousOutputScript, sighashType)
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
    tx.hashForSigning(inputIndex, Script.write(previousOutputScript), sighashType)

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
    tx.hashForSigning(inputIndex, previousOutputScript, sighashType, amount, signatureVersion)
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
   * @param tx          transaction to sign
   * @param inputIndex  index of the transaction input being signed
   * @param inputs      UTXOs spent by this transaction
   * @param sighashType signature hash type
   * @param sigVersion  signature version
   * @param tapleaf_opt when spending a tapscript, the hash of the corresponding script leaf must be provided
   * @param annex_opt   (optional) taproot annex
   */
  def hashForSigningSchnorr(tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, sigVersion: Int, tapleaf_opt: Option[ByteVector32] = None, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    tx.hashForSigningSchnorr(inputIndex, inputs, sighashType, sigVersion, tapleaf_opt, annex_opt)
  }

  /** Use this function when spending a taproot key path. */
  def hashForSigningTaprootKeyPath(tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    tx.hashForSigningTaprootKeyPath(inputIndex, inputs, sighashType, annex_opt)
  }

  /** Use this function when spending a taproot script path. */
  def hashForSigningTaprootScriptPath(tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, tapleaf: ByteVector32, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    tx.hashForSigningTaprootScriptPath(inputIndex, inputs, sighashType, tapleaf, annex_opt)
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
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): ByteVector = {
    tx.signInput(inputIndex, previousOutputScript, sighashType, amount, signatureVersion, privateKey)
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

  /**
   * Sign a taproot tx input, using the internal key path.
   *
   * @param privateKey     private key.
   * @param tx             input transaction.
   * @param inputIndex     index of the tx input that is being signed.
   * @param inputs         list of all UTXOs spent by this transaction.
   * @param sighashType    signature hash type, which will be appended to the signature (if not default).
   * @param scriptTree_opt tapscript tree of the signed input, if it has script paths.
   * @return the schnorr signature of this tx for this specific tx input.
   */
  def signInputTaprootKeyPath(privateKey: PrivateKey, tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, scriptTree_opt: Option[bitcoin.ScriptTree], annex_opt: Option[ByteVector] = None, auxrand32: Option[ByteVector32] = None): ByteVector64 = {
    tx.signInputTaprootKeyPath(privateKey, inputIndex, inputs, sighashType, scriptTree_opt, annex_opt, auxrand32)
  }

  /**
   * Sign a taproot tx input, using one of its script paths.
   *
   * @param privateKey  private key.
   * @param tx          input transaction.
   * @param inputIndex  index of the tx input that is being signed.
   * @param inputs      list of all UTXOs spent by this transaction.
   * @param sighashType signature hash type, which will be appended to the signature (if not default).
   * @param tapleaf     tapscript leaf hash of the script that is being spent.
   * @return the schnorr signature of this tx for this specific tx input and the given script leaf.
   */
  def signInputTaprootScriptPath(privateKey: PrivateKey, tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, tapleaf: ByteVector32, annex_opt: Option[ByteVector] = None, auxrand32: Option[ByteVector32] = None): ByteVector64 = {
    tx.signInputTaprootScriptPath(privateKey, inputIndex, inputs, sighashType, tapleaf, annex_opt, auxrand32)
  }

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int): Unit = {
    tx.correctlySpends(previousOutputs, scriptFlags)
  }

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit = {
    tx.correctlySpends(inputs, scriptFlags)
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
  lazy val hash: TxHash = TxHash(Crypto.hash256(Transaction.write(this, bitcoin.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)))
  lazy val txid: TxId = TxId(hash)
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

  /**
   * prepare a transaction for signing a specific input
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type
   * @return a new transaction with proper inputs and outputs according to SIGHASH_TYPE rules
   */
  def prepareForSigning(inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int): Transaction = {
    scala2kmp(this).prepareForSigning(inputIndex, previousOutputScript.toArray, sighashType)
  }

  /**
   * hash a tx for signing (pre-segwit)
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type
   * @return a hash which can be used to sign the referenced tx input
   */
  def hashForSigning(inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int): ByteVector32 = {
    ByteVector32(ByteVector.view(scala2kmp(this).hashForSigning(inputIndex, previousOutputScript.toArray, sighashType)))
  }

  /**
   * hash a tx for signing (pre-segwit)
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type
   * @return a hash which can be used to sign the referenced tx input
   */
  def hashForSigning(inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int): ByteVector32 = {
    ByteVector32(ByteVector.view(scala2kmp(this).hashForSigning(inputIndex, Script.write(previousOutputScript).toArray, sighashType)))
  }

  /**
   * hash a tx for signing
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type
   * @param amount               amount of the output claimed by this input
   * @return a hash which can be used to sign the referenced tx input
   */
  def hashForSigning(inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int, amount: Satoshi, signatureVersion: Int): ByteVector32 = {
    ByteVector32(ByteVector.view(scala2kmp(this).hashForSigning(inputIndex, previousOutputScript.toArray, sighashType, amount, signatureVersion)))
  }

  /**
   * hash a tx for signing
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type
   * @param amount               amount of the output claimed by this input
   * @return a hash which can be used to sign the referenced tx input
   */
  def hashForSigning(inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int): ByteVector32 =
    hashForSigning(inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion)

  /**
   * @param inputIndex  index of the transaction input being signed
   * @param inputs      UTXOs spent by this transaction
   * @param sighashType signature hash type
   * @param sigVersion  signature version
   * @param tapleaf_opt when spending a tapscript, the hash of the corresponding script leaf must be provided
   * @param annex_opt   (optional) taproot annex
   */
  def hashForSigningSchnorr(inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, sigVersion: Int, tapleaf_opt: Option[ByteVector32] = None, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    scala2kmp(this).hashForSigningSchnorr(inputIndex, inputs.map(scala2kmp).asJava, sighashType, sigVersion, tapleaf_opt.map(scala2kmp).orNull, annex_opt.map(scala2kmp).orNull, null)
  }

  /** Use this function when spending a taproot key path. */
  def hashForSigningTaprootKeyPath(inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    scala2kmp(this).hashForSigningTaprootKeyPath(inputIndex, inputs.map(scala2kmp).asJava, sighashType, annex_opt.map(scala2kmp).orNull)
  }

  /** Use this function when spending a taproot script path. */
  def hashForSigningTaprootScriptPath(inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, tapleaf: ByteVector32, annex_opt: Option[ByteVector] = None): ByteVector32 = {
    scala2kmp(this).hashForSigningTaprootScriptPath(inputIndex, inputs.map(scala2kmp).asJava, sighashType, scala2kmp(tapleaf), annex_opt.map(scala2kmp).orNull)
  }

  /**
   * sign a tx input
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type, which will be appended to the signature
   * @param amount               amount of the output claimed by this tx input
   * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
   * @param privateKey           private key
   * @return the encoded signature of this tx for this specific tx input
   */
  def signInput(inputIndex: Int, previousOutputScript: ByteVector, sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): ByteVector = {
    ByteVector.view(scala2kmp(this).signInput(inputIndex, scala2kmp(previousOutputScript), sighashType, amount, signatureVersion, privateKey.priv))
  }

  /**
   * sign a tx input
   *
   * @param inputIndex           index of the tx input that is being processed
   * @param previousOutputScript public key script of the output claimed by this tx input
   * @param sighashType          signature hash type, which will be appended to the signature
   * @param amount               amount of the output claimed by this tx input
   * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
   * @param privateKey           private key
   * @return the encoded signature of this tx for this specific tx input
   */
  def signInput(inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, signatureVersion: Int, privateKey: PrivateKey): ByteVector =
    signInput(inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion, privateKey)

  /**
   * Sign a taproot tx input, using the internal key path.
   *
   * @param privateKey     private key.
   * @param inputIndex     index of the tx input that is being signed.
   * @param inputs         list of all UTXOs spent by this transaction.
   * @param sighashType    signature hash type, which will be appended to the signature (if not default).
   * @param scriptTree_opt tapscript tree of the signed input, if it has script paths.
   * @return the schnorr signature of this tx for this specific tx input.
   */
  def signInputTaprootKeyPath(privateKey: PrivateKey, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, scriptTree_opt: Option[bitcoin.ScriptTree], annex_opt: Option[ByteVector] = None, auxrand32: Option[ByteVector32] = None): ByteVector64 = {
    scala2kmp(this).signInputTaprootKeyPath(privateKey, inputIndex, inputs.map(scala2kmp).asJava, sighashType, scriptTree_opt.orNull, annex_opt.map(scala2kmp).orNull, auxrand32.map(scala2kmp).orNull)
  }

  /**
   * Sign a taproot tx input, using one of its script paths.
   *
   * @param privateKey  private key.
   * @param inputIndex  index of the tx input that is being signed.
   * @param inputs      list of all UTXOs spent by this transaction.
   * @param sighashType signature hash type, which will be appended to the signature (if not default).
   * @param tapleaf     tapscript leaf hash of the script that is being spent.
   * @return the schnorr signature of this tx for this specific tx input and the given script leaf.
   */
  def signInputTaprootScriptPath(privateKey: PrivateKey, inputIndex: Int, inputs: Seq[TxOut], sighashType: Int, tapleaf: ByteVector32, annex_opt: Option[ByteVector] = None, auxrand32: Option[ByteVector32] = None): ByteVector64 = {
    scala2kmp(this).signInputTaprootScriptPath(privateKey, inputIndex, inputs.map(scala2kmp).asJava, sighashType, tapleaf, annex_opt.map(scala2kmp).orNull, auxrand32.map(scala2kmp).orNull)
  }

  def correctlySpends(previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int): Unit = {
    scala2kmp(this).correctlySpends(previousOutputs.map { case (o, t) => scala2kmp(o) -> scala2kmp(t) }.asJava, scriptFlags)
  }

  def correctlySpends(inputs: Seq[Transaction], scriptFlags: Int): Unit = {
    scala2kmp(this).correctlySpends(inputs.map(scala2kmp).asJava, scriptFlags)
  }

  override def serializer: BtcSerializer[Transaction] = Transaction
}
