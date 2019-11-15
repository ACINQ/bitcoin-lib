package fr.acinq.bitcoin

import java.math.BigInteger
import java.nio.charset.StandardCharsets

import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey, sha256}
import scodec.bits.{ByteVector, HexStringSyntax}

import scala.util.Try

/**
 * Prototype implementation of BIP Schnorr (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).
 * Just a prototype, not meant to be used anywhere (should use libsecp256k1 instead).
 */
object Schnorr {

  val p = new BigInteger(1, hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".toArray) // field size
  val n = new BigInteger(1, hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".toArray) // curve order

  /** Check if a curve point's y value is a quadratic residue modulo the field size. */
  private def isSquare(point: PublicKey): Boolean = {
    val y = point.toUncompressedBin.takeRight(32)
    val fieldExp = p.subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2))
    val legendre = new BigInteger(1, y.toArray).modPow(fieldExp, p)
    legendre == BigInteger.valueOf(1)
  }

  // NB: we currently don't expose curve points in bitcoin-lib, only public keys.
  // Schnorr makes a distinction because of x-only public keys (and the square y requirement).
  private def point(publicKey: ByteVector32): PublicKey = {
    val x = new BigInteger(1, publicKey.toArray)
    val c = x.pow(3).add(BigInteger.valueOf(7)).mod(p)
    val y = c.modPow(p.add(BigInteger.valueOf(1)).divide(BigInteger.valueOf(4)), p)
    if (c != y.modPow(BigInteger.valueOf(2), p)) {
      throw new IllegalArgumentException("invalid public key")
    } else {
      PublicKey.fromBin(hex"04" ++ publicKey ++ PrivateKey(y).value)
    }
  }

  /** Hash with a context-dependent tag. */
  def taggedHash(tag: String, data: ByteVector): ByteVector32 = {
    val t = sha256(ByteVector(tag.getBytes(StandardCharsets.UTF_8)))
    sha256(t ++ t ++ data)
  }

  def sign(data: ByteVector, privateKey: PrivateKey): ByteVector64 = {
    val dd = privateKey.bigInt
    if (dd == BigInteger.valueOf(0) || dd.compareTo(n) >= 0) {
      throw new IllegalArgumentException("invalid private key")
    }

    val P = privateKey.publicKey
    val d = if (isSquare(P)) dd else n.subtract(dd)
    val kk = new BigInteger(1, taggedHash("BIPSchnorrDerive", PrivateKey(d).value ++ data).toArray).mod(n)
    if (kk == BigInteger.valueOf(0)) {
      throw new IllegalArgumentException("invalid deterministic nonce (invalid message / private key combination)")
    }

    val R = PrivateKey(kk).publicKey
    val k = if (isSquare(R)) kk else n.subtract(kk)
    val e = new BigInteger(1, taggedHash("BIPSchnorr", R.value.drop(1) ++ P.value.drop(1) ++ data).toArray).mod(n)
    ByteVector64(R.value.drop(1) ++ PrivateKey(k.add(e.multiply(d)).mod(n)).value)
  }

  def verifySignature(data: ByteVector, signature: ByteVector64, publicKey: ByteVector32): Boolean = Try {
    val P = point(publicKey)
    val r = new BigInteger(1, signature.take(32).toArray)
    val s = new BigInteger(1, signature.takeRight(32).toArray)
    if (r.compareTo(p) >= 0 || s.compareTo(n) >= 0) {
      false
    } else {
      val e = new BigInteger(1, taggedHash("BIPSchnorr", signature.take(32) ++ publicKey ++ data).toArray).mod(n)
      val R = PrivateKey(s).publicKey - P.multiply(PrivateKey(e))
      R.value.drop(1) == signature.take(32) && isSquare(R)
    }
  } getOrElse false

}
