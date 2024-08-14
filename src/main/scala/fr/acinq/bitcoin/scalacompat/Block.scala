package fr.acinq.bitcoin.scalacompat

import KotlinUtils._

/** This is the double hash of a serialized block header. */
case class BlockHash(value: ByteVector32) {
  override def toString = value.toString
}

object BlockHash {
  def apply(blockId: BlockId): BlockHash = BlockHash(blockId.value.reverse)
}

/** This contains the same data as [BlockHash], but encoded with the opposite endianness. */
case class BlockId(value: ByteVector32) {
  override def toString = value.toString
}

object BlockId {
  def apply(blockHash: BlockHash): BlockId = BlockId(blockHash.value.reverse)
}

object Block {
  // genesis blocks
  object LivenetGenesisBlock {
    val blockId: BlockId = fr.acinq.bitcoin.Block.LivenetGenesisBlock.blockId
    val hash: BlockHash = fr.acinq.bitcoin.Block.LivenetGenesisBlock.hash
  }

  object TestnetGenesisBlock {
    val blockId: BlockId = fr.acinq.bitcoin.Block.Testnet3GenesisBlock.blockId
    val hash: BlockHash = fr.acinq.bitcoin.Block.Testnet3GenesisBlock.hash
  }

  object Testnet4GenesisBlock {
    val blockId: BlockId = fr.acinq.bitcoin.Block.Testnet4GenesisBlock.blockId
    val hash: BlockHash = fr.acinq.bitcoin.Block.Testnet4GenesisBlock.hash
  }

  object RegtestGenesisBlock {
    val blockId: BlockId = fr.acinq.bitcoin.Block.RegtestGenesisBlock.blockId
    val hash: BlockHash = fr.acinq.bitcoin.Block.RegtestGenesisBlock.hash
  }

  object SignetGenesisBlock {
    val blockId: BlockId = fr.acinq.bitcoin.Block.SignetGenesisBlock.blockId
    val hash: BlockHash = fr.acinq.bitcoin.Block.SignetGenesisBlock.hash
  }
}