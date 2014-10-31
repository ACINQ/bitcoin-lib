package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.math.BigInteger

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.{ASN1InputStream, ASN1Integer, DERSequenceGenerator, DLSequence}
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.{GeneralDigest, RIPEMD160Digest, SHA256Digest}
import org.bouncycastle.crypto.params.{ECDomainParameters, ECPrivateKeyParameters, ECPublicKeyParameters}
import org.bouncycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}

import scala.util.{Failure, Success, Try}

object Crypto {
  val params = SECNamedCurves.getByName("secp256k1")
  val curve = new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  val halfCurveOrder = params.getN().shiftRight(1)
  val zero = BigInteger.valueOf(0)
  val one = BigInteger.valueOf(1)

  /**
   * signature hash type
   *
   */
  object SignatureHashType {
    val SIGHASH_ALL = 1.toByte
    val SIGHASH_NONE = 2.toByte
    val SIGHASH_SINGLE = 3.toByte
    val SIGHASH_ANYONECANPAY = 0x80.toByte
  }

  def hash(digest: Digest)(input: Array[Byte]): Array[Byte] = {
    digest.update(input, 0, input.length)
    val out = new Array[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    out
  }

  def sha256 = hash(new SHA256Digest) _

  def ripemd160 = hash(new RIPEMD160Digest) _

  /**
   * 160 bits bitcoin hash, used mostly for address encoding
   * hash160(input) = RIPEMD160(SHA256(input))
   * @param input array of byte
   * @return the 160 bits BTC hash of input
   */
  def hash160(input: Array[Byte]): Array[Byte] = ripemd160(sha256(input))

  /**
   * 256 bits bitcoin hash
   * hash256(input) = SHA256(SHA256(input))
   * @param input array of byte
   * @return the 256 bits BTC hash of input
   */
  def hash256(input: Array[Byte]) = sha256(sha256(input))

  /**
   * An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
   * @param r first value
   * @param s second value
   * @return (r, s) in DER format
   */
  def encodeSignature(r: BigInteger, s: BigInteger): Array[Byte] = {
    // Usually 70-72 bytes
    val bos = new ByteArrayOutputStream(72)
    val seq = new DERSequenceGenerator(bos)
    seq.addObject(new ASN1Integer(r))
    seq.addObject(new ASN1Integer(s))
    seq.close()
    bos.toByteArray
  }

  def encodeSignature(t: (BigInteger, BigInteger)): Array[Byte] = encodeSignature(t._1, t._2)

    /**
   * An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
   * @param blob sigbyte data
   * @return the decoded (r, s) signature
   */
  def decodeSignature(blob: Array[Byte]): (BigInteger, BigInteger) = {
    val decoder = new ASN1InputStream(blob)
    val seq = decoder.readObject.asInstanceOf[DLSequence]
    val r = seq.getObjectAt(0).asInstanceOf[ASN1Integer]
    val s = seq.getObjectAt(1).asInstanceOf[ASN1Integer]
    decoder.close()
    (r.getPositiveValue, s.getPositiveValue)
  }

  def verifySignature(data: Array[Byte], signature: (BigInteger, BigInteger), publicKey: Array[Byte]): Boolean = {
    val (r, s) = signature
    require(r.compareTo(one) >= 0, "r must be >= 1")
    require(r.compareTo(curve.getN) < 0, "r must be < N")
    require(s.compareTo(one) >= 0, "s must be >= 1")
    require(s.compareTo(curve.getN) < 0, "s must be < N")

    val signer = new ECDSASigner
    val params = new ECPublicKeyParameters(curve.getCurve.decodePoint(publicKey), curve)
    signer.init(false, params)
    Try(signer.verifySignature(data, r, s)) match {
      case Success(result) => result
      case Failure(cause) => {
        println(cause)
        false
      }
    }
  }

  /**
   *
   * @param privateKey private key
   * @return the corresponding public key
   */
  def publicKeyFromPrivateKey(privateKey: Array[Byte]) = {
    // a private key is either 32 bytes or 33 bytes with a last byte of 0x01
    val compressed = privateKey.length match {
      case 32 => false
      case 33 if privateKey(32) == 1 => true
      case _ => throw new Exception("invalid private key")
    }
    // PubKey = G * PrivKey
    val Q = params.getG().multiply(new BigInteger(1, privateKey.take(32)))
    Q.getEncoded(compressed)
  }

  /**
   * Sign data with a private key
   * @param data data to sign
   * @param privateKey private key
   * @param randomize if true, signing the same data with the same key multiple times will produce different results. Default is 'true'
   *                  and you should specify 'false' for testing purposes only
   * @return a (r, s) ECDSA signature pair
   */
  def sign(data: Array[Byte], privateKey: Array[Byte], randomize: Boolean = true): (BigInteger, BigInteger) = {
    val signer = if (randomize) new ECDSASigner() else new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest))
    val privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), curve)
    signer.init(true, privateKeyParameters)
    val Array(r, s) = signer.generateSignature(data)

    if (s.compareTo(halfCurveOrder) > 0) {
      (r, curve.getN().subtract(s)) // if s > N/2 then s = N - s
    } else {
      (r, s)
    }
  }
}
