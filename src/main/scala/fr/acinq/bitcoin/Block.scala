package fr.acinq.bitcoin

import java.io.{InputStream, OutputStream}
import java.math.BigInteger
import java.nio.ByteOrder
import java.util

import fr.acinq.bitcoin.Protocol._

object BlockHeader extends BtcSerializer[BlockHeader] {
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
    writeUInt32(input.version.toInt, out)
    writeBytes(input.hashPreviousBlock, out)
    writeBytes(input.hashMerkleRoot, out)
    writeUInt32(input.time.toInt, out)
    writeUInt32(input.bits.toInt, out)
    writeUInt32(input.nonce.toInt, out)
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
  * @param version           Block version information, based upon the software version creating this block
  * @param hashPreviousBlock The hash value of the previous block this particular block references. Please not that
  *                          this hash is not reversed (as opposed to Block.hash)
  * @param hashMerkleRoot    The reference to a Merkle tree collection which is a hash of all transactions related to this block
  * @param time              A timestamp recording when this block was created (Will overflow in 2106[2])
  * @param bits              The calculated difficulty target being used for this block
  * @param nonce             The nonce used to generate this block… to allow variations of the header and compute different hashes
  */
case class BlockHeader(version: Long, hashPreviousBlock: BinaryData, hashMerkleRoot: BinaryData, time: Long, bits: Long, nonce: Long) extends BtcSerializable[BlockHeader] {
  require(hashPreviousBlock.length == 32, "hashPreviousBlock must be 32 bytes")
  require(hashMerkleRoot.length == 32, "hashMerkleRoot must be 32 bytes")
  lazy val hash: BinaryData = Crypto.hash256(BlockHeader.write(this))

  override def serializer: BtcSerializer[BlockHeader] = BlockHeader
}

object Block extends BtcSerializer[Block] {
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
    require(util.Arrays.equals(input.header.hashMerkleRoot, MerkleTree.computeRoot(input.tx.map(_.hash))), "invalid block:  merkle root mismatch")
    require(input.tx.map(_.txid).toSet.size == input.tx.size, "invalid block: duplicate transactions")
    input.tx.map(Transaction.validate)
  }

  // genesis blocks
  val LivenetGenesisBlock = {
    val script = OP_PUSHDATA(writeUInt32(486604799L)) :: OP_PUSHDATA(BinaryData("04")) :: OP_PUSHDATA("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".getBytes("UTF-8")) :: Nil
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

  val TestnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458))

  val RegtestGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 0x207fffffL, nonce = 2, time = 1296688602))

  val SegnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 503447551, time = 1452831101, nonce = 0))

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

  /**
    *
    * @param tx coinbase transaction
    * @return the witness reserved value included in the input of this tx if any
    */
  def witnessReservedValue(tx: Transaction) : Option[BinaryData] = tx.txIn(0).witness match {
    case ScriptWitness(Seq(nonce)) if nonce.length == 32 => Some(nonce)
    case _ => None
  }

  /**
    *
    * @param tx coinbase transaction
    * @return the witness commitment included in this transaction, if any
    */
  def witnessCommitment(tx: Transaction): Option[BinaryData] = tx.txOut.map(o => Script.parse(o.publicKeyScript)).reverse.collectFirst {
    // we've reversed the outputs because if there are more than one scriptPubKey matching the pattern, the one with
    // the highest output index is assumed to be the commitment.
    case OP_RETURN :: OP_PUSHDATA(commitmentHeader, _) :: Nil if commitmentHeader.length == 36 && Protocol.uint32(commitmentHeader.take(4), ByteOrder.BIG_ENDIAN) == 0xaa21a9edL => commitmentHeader.takeRight(32)
  }

  /**
    * Checks the witness commitment of a block
    * @param block block
    * @return true if the witness commitment for this block is valid, or if this block does not contain a witness commitment
    *         nor any segwit transactions.
    */
  def checkWitnessCommitment(block: Block) : Boolean = {
    val coinbase = block.tx.head
    (witnessReservedValue(coinbase), witnessCommitment(coinbase)) match {
      case (Some(nonce), Some(commitment)) =>
        val rootHash = MerkleTree.computeRoot(Hash.Zeroes +: block.tx.tail.map(_.whash))
        val commitmentHash = Crypto.hash256(rootHash ++ nonce)
        commitment == commitmentHash
      case _ if block.tx.exists(_.hasWitness) => false // block has segwit transactions but no witness commitment
      case _ => true
    }
  }
}

/**
  * Bitcoin block
  *
  * @param header block header
  * @param tx     transactions
  */
case class Block(header: BlockHeader, tx: Seq[Transaction]) extends BtcSerializable[Block] {
  lazy val hash = header.hash

  // hash is reversed here (same as tx id)
  lazy val blockId = BinaryData(hash.reverse)

  override def serializer: BtcSerializer[Block] = Block
}

