package fr.acinq.bitcoin

import java.io._
import java.math.BigInteger
import java.net.InetAddress
import java.util

import scala.collection.mutable.ArrayBuffer

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */

object BinaryData {
  def apply(hex: String) : BinaryData = hex
}

case class BinaryData(data: Seq[Byte]) {
  def length = data.length
  override def toString = toHexString(data)
}


trait BtcMessage[T] {
  /**
   * write a message to a stream
   * @param t message
   * @param out output stream
   */
  def write(t: T, out: OutputStream): Unit

  /**
   * write a message to a byte array
   * @param t message
   * @return a serialized message
   */
  def write(t: T): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    write(t, out)
    out.toByteArray
  }

  /**
   * read a message from a stream
   * @param in input stream
   * @return a deserialized message
   */
  def read(in: InputStream): T

  /**
   * read a message from a byte array
   * @param in serialized message
   * @return a deserialized message
   */
  def read(in: Seq[Byte]): T = read(new ByteArrayInputStream(in.toArray))

  /**
   * read a message from a hex string
   * @param in message binary data in hex format
   * @return a deserialized message of type T
   */
  def read(in: String): T = read(fromHexString(in))

  def validate(t: T): Unit = {}
}


object OutPoint extends BtcMessage[OutPoint] {
  def apply(tx: Transaction, index: Int) = new OutPoint(tx.hash, index)

  override def read(input: InputStream): OutPoint = OutPoint(hash(input), uint32(input))

  override def write(input: OutPoint, out: OutputStream) = {
    out.write(input.hash)
    writeUInt32(input.index, out)
  }

  def isCoinbase(input: OutPoint) = input.index == 0xffffffffL && input.hash == Hash.Zeroes

  def isNull(input: OutPoint) = isCoinbase(input)

}

/**
 * an out point is a reference to a specific output in a specific transaction that we want to claim
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
  def apply(outPoint: OutPoint, signatureScript: Seq[ScriptElt], sequence: Long) : TxIn = new TxIn(outPoint, Script.write(signatureScript), sequence)

  override def read(input: InputStream): TxIn = TxIn(outPoint = OutPoint.read(input), signatureScript = script(input), sequence = uint32(input))

  override def write(input: TxIn, out: OutputStream) = {
    OutPoint.write(input.outPoint, out)
    writeScript(input.signatureScript, out)
    writeUInt32(input.sequence, out)
  }

  override def validate(input: TxIn) : Unit = {
    require(input.signatureScript.length <= MaxScriptElementSize, s"signature script is ${input.signatureScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }

  def coinbase(script: Array[Byte]): TxIn = {
    require(script.length >= 2 && script.length <= 100, "coinbase script length must be between 2 and 100")
    TxIn(OutPoint(new Array[Byte](32), 0xffffffffL), script, sequence = 0xffffffffL)
  }
}

/**
 * Transaction input
 * @param outPoint Previous output transaction reference
 * @param signatureScript Computational Script for confirming transaction authorization
 * @param sequence Transaction version as defined by the sender. Intended for "replacement" of transactions when
 *                 information is updated before inclusion into a block. Unused for now.
 */
case class TxIn(outPoint: OutPoint, signatureScript: BinaryData, sequence: Long)

object TxOut extends BtcMessage[TxOut] {
  def apply(amount: Long, publicKeyScript: Seq[ScriptElt]) : TxOut = new TxOut(amount, Script.write(publicKeyScript))

  override def read(input: InputStream): TxOut = TxOut(uint64(input), script(input))

  override def write(input: TxOut, out: OutputStream) = {
    writeUInt64(input.amount, out)
    writeScript(input.publicKeyScript, out)
  }

  override def validate(input: TxOut) : Unit = {
    import input._
    require(amount >= 0, s"invalid txout amount: $amount")
    require(amount <= MaxMoney, s"invalid txout amount: $amount")
    require(publicKeyScript.length < MaxScriptElementSize, s"public key script is ${publicKeyScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }
}

/**
 * Transaction output
 * @param amount amount in Satoshis
 * @param publicKeyScript Usually contains the public key as a Bitcoin script setting up conditions to claim this output.
 */
case class TxOut(amount: Long, publicKeyScript: BinaryData)

object Transaction extends BtcMessage[Transaction] {
  override def read(input: InputStream): Transaction = {
    val version = uint32(input)
    val nbrIn = varint(input)
    val txIn = ArrayBuffer.empty[TxIn]
    for (i <- 1L to nbrIn) {
      txIn += TxIn.read(input)
    }
    val txOut = ArrayBuffer.empty[TxOut]
    val nbrOut = varint(input)
    for (i <- 1L to nbrOut) {
      txOut += TxOut.read(input)
    }
    val lockTime = uint32(input)
    Transaction(version, txIn.toList, txOut.toList, lockTime)
  }

  override def write(input: Transaction, out: OutputStream) = {
    writeUInt32(input.version, out)
    writeVarint(input.txIn.length, out)
    input.txIn.map(t => TxIn.write(t, out))
    writeVarint(input.txOut.length, out)
    input.txOut.map(t => TxOut.write(t, out))
    writeUInt32(input.lockTime, out)
  }

  override def validate(input: Transaction) : Unit = {
    require(input.txIn.nonEmpty, "input list cannot be empty")
    require(input.txOut.nonEmpty, "output list cannot be empty")
    require(Transaction.write(input).size <= MaxBlockSize)
    require(input.txOut.map(_.amount).sum <= MaxMoney, "sum of outputs amount is invalid")
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
          else TxOut(-1, Array.empty[Byte])
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
   * @param sighashType signature hash type
   * @param privateKey private key
   * @param randomize if false, the output signature will not be randomized (use for testing only)
   * @return the encoded signature of this tx for this specific tx input
   */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: Array[Byte], sighashType: Int, privateKey: Array[Byte], randomize: Boolean = true): Array[Byte] = {
    val hash = hashForSigning(tx, inputIndex, previousOutputScript, sighashType)
    val (r, s) = Crypto.sign(hash, privateKey.take(32), randomize)
    Crypto.encodeSignature(r, s)
  }

  /**
   * Sign a transaction. Cannot partially sign. All the input are signed with SIGHASH_ALL
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
      val sigScript = Script.write(OP_PUSHDATA(sig :+ 1.toByte) :: OP_PUSHDATA(publicKey) :: Nil)
      input.txIn(i).copy(signatureScript = sigScript)
    }

    input.copy(txIn = signedInputs)
  }

  /**
   * checks that a transaction correctly spends its inputs (i.e properly signed)
   * @param tx transaction to be checked
   * @param inputs previous tx that are being spent
   * @param scriptFlags script execution flags
   * @throws AssertionError is the transaction is not valid (i.e executing input and output scripts does not yield "true")
   */
  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit = {
    val txMap = inputs.map(t => t.txid -> t).toMap
    val prevoutMap = for (i <- 0 until tx.txIn.length) yield tx.txIn(i).outPoint -> txMap(tx.txIn(i).outPoint.txid).txOut(tx.txIn(i).outPoint.index.toInt).publicKeyScript
    correctlySpends(tx, prevoutMap.toMap, scriptFlags)
  }

  /**
   * checks that a transaction correctly spends its inputs (i.e properly signed)
   * @param tx transaction to be checked
   * @param prevoutScripts map where keys are OutPoint (previous tx ids and vout index) and values are previous output pubkey scripts)
   * @param scriptFlags script execution flags
   * @throws AssertionError is the transaction is not valid (i.e executing input and output scripts does not yield "true")
   */
  def correctlySpends(tx: Transaction, prevoutScripts: Map[OutPoint, BinaryData], scriptFlags: Int): Unit = {
    for (i <- 0 until tx.txIn.length if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
      val prevOutputScript = prevoutScripts(tx.txIn(i).outPoint)
      val ctx = new Script.Context(tx, i)
      val runner = new Script.Runner(ctx, scriptFlags)
      assert(runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript))
    }
  }
}

/**
 * data for signing pay2pk transaction
 * @param prevPubKeyScript previous output public key script
 * @param privateKey private key associated with the previous output public key
 */
case class SignData(prevPubKeyScript: BinaryData, privateKey: BinaryData)

/**
 * Transaction
 * @param version Transaction data format version
 * @param txIn Transaction inputs
 * @param txOut Transaction outputs
 * @param lockTime The block number or timestamp at which this transaction is locked
 */
case class Transaction(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long) {
  lazy val hash : BinaryData = Crypto.hash256(Transaction.write(this))
  lazy val txid = BinaryData(hash.reverse)
}

object BlockHeader extends BtcMessage[BlockHeader] {
  override def read(input: InputStream): BlockHeader = {
    val version = uint32(input)
    val hashPreviousBlock = hash(input)
    val hashMerkleRoot = hash(input)
    val time = uint32(input)
    val bits = uint32(input)
    val nonce = uint32(input)
    BlockHeader(version, hashPreviousBlock, hashMerkleRoot, time, bits, nonce)
  }

  override def write(input: BlockHeader, out: OutputStream) = {
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
  lazy val hash:BinaryData = Crypto.hash256(BlockHeader.write(this))
}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
 */
object MerkleTree {
  def computeRootRaw(tree: Seq[Array[Byte]]): Array[Byte] = tree.length match {
    case 1 => tree(0)
    case n if n % 2 != 0 => computeRootRaw(tree :+ tree.last) // append last element again
    case _ => computeRootRaw(tree.grouped(2).map(a => Crypto.hash256(a(0) ++ a(1))).toSeq)
  }

  /**
   *
   * @param transactions list of transactions
   * @return the Merkle root of the treed built from the input transactions
   */
  def computeRoot(transactions: Seq[Transaction]): Array[Byte] = computeRootRaw(transactions.map(t => Crypto.hash256(Transaction.write(t))))
}

object Block extends BtcMessage[Block] {
  override def read(input: InputStream): Block = {
    val raw = bytes(input, 80)
    val header = BlockHeader.read(new ByteArrayInputStream(raw))
    val nbrTx = varint(input)
    val tx = ArrayBuffer.empty[Transaction]
    for (i <- 1L to nbrTx) {
      tx += Transaction.read(input)
    }
    Block(header, tx)
  }

  override def write(input: Block, out: OutputStream) = {
    BlockHeader.write(input.header, out)
    writeVarint(input.tx.length, out)
    input.tx.map(t => Transaction.write(t, out))
  }

  override def validate(input: Block) : Unit = {
    BlockHeader.validate(input.header)
    require(util.Arrays.equals(input.header.hashMerkleRoot, MerkleTree.computeRoot(input.tx)), "invalid block:  merkle root mismatch")
    require(input.tx.map(_.txid).toSet.size == input.tx.size, "invalid block: duplicate transactions")
    input.tx.map(Transaction.validate)
  }

  // genesis block
  val LivenetGenesisBlock = {
    val script = OP_PUSHDATA(writeUInt32(486604799L)) :: OP_PUSHDATA(writeUInt8(4)) :: OP_PUSHDATA("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".getBytes("UTF-8")) :: Nil
    val scriptPubKey = OP_PUSHDATA("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") :: OP_CHECKSIG :: Nil
    Block(
      BlockHeader(version = 1, hashPreviousBlock = new Array[Byte](32), hashMerkleRoot = fromHexString("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"), time = 1231006505, bits = 0x1d00ffff, nonce = 2083236893),
      List(
        Transaction(version = 1,
          txIn = List(TxIn.coinbase(Script.write(script))),
          txOut = List(TxOut(amount = 50 * Coin, publicKeyScript = Script.write(scriptPubKey))),
          lockTime = 0))
    )
  }

  // testnet genesis block
  val TestnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458))

  val RegtestGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 0x207fffffL, nonce = 2, time = 1296688602))

  // mine.header.copy(bits = 0x0x207fffffL, nonce = 2, time = 1296688602)
  /**
   * Proof of work: hash(block) <= target difficulty
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
 * @param header block header
 * @param tx transactions
 */
case class Block(header: BlockHeader, tx: Seq[Transaction]) {
  lazy val hash = header.hash

  // hash is reversed here (same as tx id)
  lazy val blockId = BinaryData(hash.reverse)
}

object Address {
  val LivenetPubkeyVersion = 0.toByte
  val LivenetScriptVersion = 5.toByte
  val TestnetPubkeyVersion = 111.toByte
  val TestnetScriptVersion = 196.toByte

  /**
   * an address is just an encoded public key hash
   * @param version 0 for livenet pubkey, 111 for the testnet pubkey, 5 for livenet script, 196 for testnet script
   * @param publicKeyHash public key hash
   * @return the address associated to he public key
   */
  def encode(version: Byte, publicKeyHash: Array[Byte]): String = Base58Check.encode(version, publicKeyHash)

  /**
   *
   * @param address btc address
   * @return a (version, public key hash) tuple
   */
  def decode(address: String): (Byte, Array[Byte]) = Base58Check.decode(address)
}

object Message extends BtcMessage[Message] {
  val MagicMain = 0xD9B4BEF9L
  val MagicTestNet = 0xDAB5BFFAL
  val MagicTestnet3 = 0x0709110BL
  val MagicNamecoin = 0xFEB4BEF9L

  override def read(in: InputStream): Message = {
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

  override def write(input: Message, out: OutputStream) = {
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
 * @param magic Magic value indicating message origin network, and used to seek to next message when stream state is unknown
 * @param command ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
 * @param payload The actual data
 */
case class Message(magic: Long, command: String, payload: BinaryData) {
  require(command.length <= 12)
}

object NetworkAddressWithTimestamp extends BtcMessage[NetworkAddressWithTimestamp] {
  override def read(in: InputStream): NetworkAddressWithTimestamp = {
    val time = uint32(in)
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    require(toHexString(raw.take(12)) == "00000000000000000000ffff", "IPV4 only")
    val address = InetAddress.getByAddress(raw.takeRight(4))
    val port = uint16BigEndian(in)
    NetworkAddressWithTimestamp(time, services, address, port)
  }

  override def write(input: NetworkAddressWithTimestamp, out: OutputStream) = {
    writeUInt32(input.time, out)
    writeUInt64(input.services, out)
    out.write(fromHexString("00000000000000000000ffff"))
    out.write(input.address.getAddress)
    writeUInt16BigEndian(input.port, out)
  }
}

case class NetworkAddressWithTimestamp(time: Long, services: Long, address: InetAddress, port: Long)

object NetworkAddress extends BtcMessage[NetworkAddress] {
  override def read(in: InputStream): NetworkAddress = {
    val services = uint64(in)
    val raw = new Array[Byte](16)
    in.read(raw)
    //require(toHexString(raw.take(12)) == "00000000000000000000ffff", "IPV4 only")
    val address = InetAddress.getByAddress(raw.takeRight(4))
    val port = uint16BigEndian(in)
    NetworkAddress(services, address, port)
  }

  override def write(input: NetworkAddress, out: OutputStream) = {
    writeUInt64(input.services, out)
    out.write(fromHexString("00000000000000000000ffff"))
    out.write(input.address.getAddress)
    writeUInt16BigEndian(input.port, out) // wtf ?? why BE there ?
  }
}

case class NetworkAddress(services: Long, address: InetAddress, port: Long)

object Version extends BtcMessage[Version] {
  override def read(in: InputStream): Version = {
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

  override def write(input: Version, out: OutputStream) = {
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
  override def write(t: Addr, out: OutputStream): Unit = {
    writeVarint(t.addresses.length, out)
    t.addresses.map(a => NetworkAddressWithTimestamp.write(a, out))
  }

  override def read(in: InputStream): Addr = {
    val length = varint(in)
    require(length <= 1000, "invalid length")
    val addr = ArrayBuffer.empty[NetworkAddressWithTimestamp]
    for (i <- 1L to length) {
      addr += NetworkAddressWithTimestamp.read(in)
    }
    Addr(addr.toList)
  }
}

case class Addr(addresses: Seq[NetworkAddressWithTimestamp])

object InventoryVector extends BtcMessage[InventoryVector] {
  val ERROR = 0L
  val MSG_TX = 1L
  val MSG_BLOCK = 2L

  override def write(t: InventoryVector, out: OutputStream): Unit = {
    writeUInt32(t.`type`, out)
    out.write(t.hash)
  }

  override def read(in: InputStream): InventoryVector = InventoryVector(uint32(in), hash(in))
}

case class InventoryVector(`type`: Long, hash: BinaryData) {
  require(hash.length == 32, "invalid hash length")
}

object Inventory extends BtcMessage[Inventory] {
  override def write(t: Inventory, out: OutputStream): Unit = {
    writeVarint(t.inventory.length, out)
    t.inventory.map(i => InventoryVector.write(i, out))
  }

  override def read(in: InputStream): Inventory = {
    val length = varint(in)
    require(length < 1000, "invalid length")
    val vector = ArrayBuffer.empty[InventoryVector]
    for (i <- 1L to length) {
      vector += InventoryVector.read(in)
    }
    Inventory(vector.toList)
  }
}

case class Inventory(inventory: Seq[InventoryVector])

object Getheaders extends BtcMessage[Getheaders] {
  override def write(t: Getheaders, out: OutputStream): Unit = {
    writeUInt32(t.version, out)
    writeVarint(t.locatorHashes.size, out)
    t.locatorHashes.map(h => out.write(h))
    out.write(t.stopHash)
  }

  override def read(in: InputStream): Getheaders = {
    val version = uint32(in)
    val vector = ArrayBuffer.empty[BinaryData]
    val count = varint(in)
    for (i <- 1L to count) {
      vector += hash(in)
    }
    val stopHash = hash(in)
    Getheaders(version, vector.toSeq, stopHash)
  }
}

case class Getheaders(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) {
  locatorHashes.map(h => require(h.length == 32))
  require(stopHash.length == 32)
}

object Headers extends BtcMessage[Headers] {
  override def write(t: Headers, out: OutputStream): Unit = {
    writeVarint(t.headers.size, out)
    t.headers.map(h => {
      BlockHeader.write(h, out)
      writeVarint(0, out)
    })
  }

  override def read(in: InputStream): Headers = {
    val vector = ArrayBuffer.empty[BlockHeader]
    val count = varint(in)
    for (i <- 1L to count) {
      vector += BlockHeader.read(in)
      val dummy = varint(in)
      require(dummy == 0, s"header in headers message ends with $dummy, should be 0 instead")
    }
    Headers(vector.toSeq)
  }
}

case class Headers(headers: Seq[BlockHeader])

object Getblocks extends BtcMessage[Getblocks] {
  override def write(t: Getblocks, out: OutputStream): Unit = {
    writeUInt32(t.version, out)
    writeVarint(t.locatorHashes.size, out)
    t.locatorHashes.map(h => out.write(h))
    out.write(t.stopHash)
  }

  override def read(in: InputStream): Getblocks = {
    val version = uint32(in)
    val vector = ArrayBuffer.empty[BinaryData]
    val count = varint(in)
    for (i <- 1L to count) {
      vector += hash(in)
    }
    val stopHash = hash(in)
    Getblocks(version, vector.toSeq, stopHash)
  }
}

case class Getblocks(version: Long, locatorHashes: Seq[BinaryData], stopHash: BinaryData) {
  locatorHashes.map(h => require(h.length == 32))
  require(stopHash.length == 32)
}

object Getdata extends BtcMessage[Getdata] {
  override def write(t: Getdata, out: OutputStream): Unit = {
    writeVarint(t.inventory.size, out)
    t.inventory.map(i => InventoryVector.write(i, out))
  }

  override def read(in: InputStream): Getdata = {
    val vector = ArrayBuffer.empty[InventoryVector]
    val count = varint(in)
    for (i <- 1L to count) {
      vector += InventoryVector.read(in)
    }
    Getdata(vector.toSeq)
  }
}

case class Getdata(inventory: Seq[InventoryVector])

object Reject extends BtcMessage[Reject] {
  override def write(t: Reject, out: OutputStream): Unit = {
    writeVarstring(t.message, out)
    writeUInt8(t.code, out)
    writeVarstring(t.reason, out)
  }

  override def read(in: InputStream): Reject = {
    val message = varstring(in)
    val code = uint8(in)
    val reason = varstring(in)
    Reject(message, code, reason, Array.empty[Byte])
  }
}

case class Reject(message: String, code: Long, reason: String, data: BinaryData)