package fr.acinq.bitcoinscala.reference

import fr.acinq.bitcoinscala.{BlockHeader, ByteVector32}
import org.scalatest.FunSuite

class PowSpec extends FunSuite {
  test("calculate next work required") {
    val header = BlockHeader(version = 2, hashPreviousBlock = ByteVector32.Zeroes, hashMerkleRoot = ByteVector32.Zeroes, time = 0L, bits = 0L, nonce = 0L)

    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161) === 0x1d00d86aL)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505) === 0x1d00ffffL)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237) === 0x1c0168fdL)
  }
}
