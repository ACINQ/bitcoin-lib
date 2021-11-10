package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.KotlinUtils._

object Block {
  // genesis blocks
  object LivenetGenesisBlock {
    val blockId: ByteVector32 = fr.acinq.bitcoin.Block.LivenetGenesisBlock.blockId
    val hash: ByteVector32 = fr.acinq.bitcoin.Block.LivenetGenesisBlock.hash
  }

  object TestnetGenesisBlock {
    val blockId: ByteVector32 = fr.acinq.bitcoin.Block.TestnetGenesisBlock.blockId
    val hash: ByteVector32 = fr.acinq.bitcoin.Block.TestnetGenesisBlock.hash
  }

  object RegtestGenesisBlock {
    val blockId: ByteVector32 = fr.acinq.bitcoin.Block.RegtestGenesisBlock.blockId
    val hash: ByteVector32 = fr.acinq.bitcoin.Block.RegtestGenesisBlock.hash
  }

  object SegnetGenesisBlock {
    val blockId: ByteVector32 = fr.acinq.bitcoin.Block.SegnetGenesisBlock.blockId
    val hash: ByteVector32 = fr.acinq.bitcoin.Block.SegnetGenesisBlock.hash
  }
}