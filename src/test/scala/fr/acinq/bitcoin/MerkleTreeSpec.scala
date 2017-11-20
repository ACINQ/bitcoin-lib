package fr.acinq.bitcoin


import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner


class MerkleTreeSpec extends FlatSpec {
  "MerkleTree" should "compute the root of a merkle tree" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block1.dat")
    val block = Block.read(stream)
    assert(MerkleTree.computeRoot(block.tx.map(_.hash)) === block.header.hashMerkleRoot)
  }
}
