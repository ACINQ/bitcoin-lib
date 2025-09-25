package fr.acinq.bitcoin.scalacompat

import scodec.bits.ByteVector

/** Simple binary tree structure containing taproot spending scripts. */
sealed trait ScriptTree {

  /** Compute the merkle root of the script tree. */
  def hash(): ByteVector32 = KotlinUtils.kmp2scala(KotlinUtils.scala2kmp(this).hash())

  /** Return the first leaf with a matching script, if any. */
  def findScript(script: ByteVector): Option[ScriptTree.Leaf] = this match {
    case leaf: ScriptTree.Leaf if leaf.script == script => Some(leaf)
    case _: ScriptTree.Leaf => None
    case branch: ScriptTree.Branch => branch.left.findScript(script).orElse(branch.right.findScript(script))
  }

  /** Return the first leaf with a matching leaf hash, if any. */
  def findScript(leafHash: ByteVector32): Option[ScriptTree.Leaf] = this match {
    case leaf: ScriptTree.Leaf if leaf.hash() == leafHash => Some(leaf)
    case _: ScriptTree.Leaf => None
    case branch: ScriptTree.Branch => branch.left.findScript(leafHash).orElse(branch.right.findScript(leafHash))
  }

  /**
   * Compute a merkle proof for the given script leaf.
   * This merkle proof is encoded for creating control blocks in taproot script path witnesses.
   * If the leaf doesn't belong to the script tree, this function will return None.
   */
  def merkleProof(leafHash: ByteVector32): Option[ByteVector] = {
    val proof_opt = KotlinUtils.scala2kmp(this).merkleProof(KotlinUtils.scala2kmp(leafHash))
    if (proof_opt == null) None else Some(ByteVector(proof_opt))
  }

}

object ScriptTree {
  /**
   * Multiple spending scripts can be placed in the leaves of a taproot tree. When using one of those scripts to spend
   * funds, we only need to reveal that specific script and a merkle proof that it is a leaf of the tree.
   *
   * @param script      serialized spending script.
   * @param leafVersion tapscript version.
   */
  case class Leaf(script: ByteVector, leafVersion: Int) extends ScriptTree

  object Leaf {
    // @formatter:off
    def apply(script: ByteVector): Leaf = Leaf(script, fr.acinq.bitcoin.Script.TAPROOT_LEAF_TAPSCRIPT)
    def apply(script: Seq[ScriptElt]): Leaf = Leaf(script, fr.acinq.bitcoin.Script.TAPROOT_LEAF_TAPSCRIPT)
    def apply(script: Seq[ScriptElt], leafVersion: Int): Leaf = Leaf(Script.write(script), leafVersion)
    // @formatter:on
  }

  case class Branch(left: ScriptTree, right: ScriptTree) extends ScriptTree
}
