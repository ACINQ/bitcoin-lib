package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.math.BigInteger

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.{ASN1InputStream, ASN1Integer, DERSequenceGenerator, DLSequence}
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests._
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.{ECDomainParameters, ECPrivateKeyParameters, ECPublicKeyParameters, KeyParameter}
import org.bouncycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.bouncycastle.math.ec.ECPoint

import scala.annotation.tailrec

object Crypto {
  val params = SECNamedCurves.getByName("secp256k1")
  val curve = new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  val halfCurveOrder = params.getN().shiftRight(1)
  val zero = BigInteger.valueOf(0)
  val one = BigInteger.valueOf(1)

  // a private key is just a number
  type PrivateKey = Scalar

  // a public key is a point on the secp256k1 curve
  type PublicKey = Point

  object PrivateKey {
    def fromBase58(value: String, prefix: Byte): PrivateKey = {
      val (`prefix`, data) = Base58Check.decode(value)
      Scalar(data)
    }
  }

  object PublicKey {

    sealed trait Encoding

    case object Uncompressed extends Encoding

    case object Compressed extends Encoding

    case object Hybrid extends Encoding

    def fromBase58(value: String, prefix: Byte): PublicKey = {
      val (`prefix`, data) = Base58Check.decode(value)
      Point(data)
    }
  }

  private def fixSize(data: BinaryData): BinaryData = data.length match {
    case 32 => data
    case length if length < 32 => Array.fill(32 - length)(0.toByte) ++ data
  }

  /**
    *
    * @param value      value to initialize this scalar with
    * @param compressed if true, points generated from this scalar will be compressed
    */
  case class Scalar(value: BigInteger, compressed: Boolean = true) {
    def add(scalar: Scalar): Scalar = Scalar(value.add(scalar.value)).mod(Crypto.curve.getN)

    def substract(scalar: Scalar): Scalar = Scalar(value.subtract(scalar.value)).mod(Crypto.curve.getN)

    def multiply(scalar: Scalar): Scalar = Scalar(value.multiply(scalar.value).mod(Crypto.curve.getN))

    /**
      *
      * @return a binary representation of this value: 32 bytes if not compressed, 33 bytes with a last byte of '1' if compressed
      */
    def toBin: BinaryData = {
      val bin = fixSize(value.toByteArray.dropWhile(_ == 0))
      if (compressed) bin :+ 1.toByte else bin
    }

    /**
      *
      * @return this * G where G is the curve generator
      */
    def toPoint: Point = Point(params.getG().multiply(value), if (compressed) PublicKey.Compressed else PublicKey.Uncompressed)
  }

  object Scalar {
    def apply(data: BinaryData): Scalar = data.length match {
      case 32 => new Scalar(new BigInteger(1, data), compressed = false)
      case 33 if data.last == 1 => new Scalar(new BigInteger(1, data.take(32).toArray), compressed = true)
    }
  }

  implicit def scalar2biginteger(scalar: Scalar): BigInteger = scalar.value

  implicit def biginteger2scalar(value: BigInteger): Scalar = Scalar(value)

  implicit def bin2scalar(value: BinaryData): Scalar = Scalar(value)

  implicit def scalar2bin(scalar: Scalar): BinaryData = scalar.toBin

  /**
    * Curve point
    *
    * @param value    ecPoint to initialize this point with
    * @param encoding if true, this point will be encoded in compressed format
    */
  case class Point(value: ECPoint, encoding: PublicKey.Encoding = PublicKey.Compressed) {
    def add(point: Point): Point = Point(value.add(point.value))

    def multiply(scalar: Scalar): Point = Point(value.multiply(scalar.value))

    /**
      *
      * @return a binary representation of this point in DER format
      */
    def toBin: BinaryData = value.getEncoded(if (encoding == PublicKey.Uncompressed) false else true)

    /**
      *
      * @return the hash160 of the binary representation of this point. This can be used to generated addresses (the address
      *         of a public key is he base58 encoding of its hash)
      */
    def hash: BinaryData = Crypto.hash160(toBin)
  }

  object Point {
    def apply(data: BinaryData): Point = {
      data.length match {
        case 65 if data.head == 4 => Point(curve.getCurve.decodePoint(data), PublicKey.Uncompressed)
        case 65 if data.head == 6 || data.head == 7 => Point(curve.getCurve.decodePoint(data), PublicKey.Hybrid)
        case 33 if data.head == 2 || data.head == 3 => Point(curve.getCurve.decodePoint(data), PublicKey.Compressed)
      }
    }
  }

  implicit def point2ecpoint(point: Point): ECPoint = point.value

  implicit def ecpoint2point(value: ECPoint): Point = Point(value)

  implicit def point2bin(point: Point): BinaryData = point.toBin

  implicit def bin2point(data: BinaryData): Point = Point(data)

  def hmac512(key: Seq[Byte], data: Seq[Byte]): BinaryData = {
    val mac = new HMac(new SHA512Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length)
    val out = new Array[Byte](64)
    mac.doFinal(out, 0)
    out
  }

  def hash(digest: Digest)(input: Seq[Byte]): BinaryData = {
    digest.update(input.toArray, 0, input.length)
    val out = new Array[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    out
  }

  def sha1 = hash(new SHA1Digest) _

  def sha256 = hash(new SHA256Digest) _

  def ripemd160 = hash(new RIPEMD160Digest) _

  /**
    * 160 bits bitcoin hash, used mostly for address encoding
    * hash160(input) = RIPEMD160(SHA256(input))
    *
    * @param input array of byte
    * @return the 160 bits BTC hash of input
    */
  def hash160(input: Seq[Byte]) = ripemd160(sha256(input))

  /**
    * 256 bits bitcoin hash
    * hash256(input) = SHA256(SHA256(input))
    *
    * @param input array of byte
    * @return the 256 bits BTC hash of input
    */
  def hash256(input: Seq[Byte]) = sha256(sha256(input))

  /**
    * An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
    *
    * @param r first value
    * @param s second value
    * @return (r, s) in DER format
    */
  def encodeSignature(r: BigInteger, s: BigInteger): BinaryData = {
    // Usually 70-72 bytes
    val bos = new ByteArrayOutputStream(72)
    val seq = new DERSequenceGenerator(bos)
    seq.addObject(new ASN1Integer(r))
    seq.addObject(new ASN1Integer(s))
    seq.close()
    bos.toByteArray
  }

  def encodeSignature(t: (BigInteger, BigInteger)): BinaryData = encodeSignature(t._1, t._2)

  def isDERSignature(sig: Seq[Byte]): Boolean = {
    require(sig.length >= 9 && sig.length <= 73)
    require(sig(0) == 0x30.toByte)
    require(sig(1) == sig.length - 3)
    require(sig(2) == 0x02.toByte)

    val lenR = sig(3)
    require(lenR > 0 && lenR + 5 < sig.length)
    require((sig(4) & 0x80) == 0)
    if (lenR > 1 && sig(4) == 0) require((sig(5) & 0x80) != 0)

    require(sig(lenR + 4) == 0x02.toByte)
    val lenS = sig(lenR + 5)
    require(lenS > 0)
    require(lenR + lenS + 7 == sig.length)
    require((sig(lenR + 6) & 0x80) == 0)
    if (lenS > 1 && sig(lenR + 6) == 0) require((sig(lenR + 7) & 0x80) != 0)

    true
  }

  def isLowDERSignature(sig: Seq[Byte]): Boolean = isDERSignature(sig) && {
    val (_, s) = decodeSignature(sig)
    s.compareTo(halfCurveOrder) <= 0
  }

  def checkSignatureEncoding(sig: Seq[Byte], flags: Int): Boolean = {
    import ScriptFlags._
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sig.isEmpty) true
    else if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !isDERSignature(sig)) false
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !isLowDERSignature(sig)) false
    else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !isDefinedHashtypeSignature(sig)) false
    else true
  }

  def checkPubKeyEncoding(key: Seq[Byte], flags: Int, sigVersion: Int): Boolean = {
    if ((flags & ScriptFlags.SCRIPT_VERIFY_STRICTENC) != 0) require(isPubKeyCompressedOrUncompressed(key), "invalid public key")
    // Only compressed keys are accepted in segwit
    if ((flags & ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigVersion == SigVersion.SIGVERSION_WITNESS_V0) require(isPubKeyCompressed(key), "public key must be compressed in segwit")
    true
  }

  def isPubKeyValid(key: Seq[Byte]): Boolean = key.length match {
    case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isPubKeyCompressedOrUncompressed(key: Seq[Byte]): Boolean = key.length match {
    case 65 if key(0) == 4 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isPubKeyCompressed(key: Seq[Byte]): Boolean = key.length match {
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isPrivateKeyCompressed(key: PrivateKey): Boolean = key.compressed

  def isDefinedHashtypeSignature(sig: Seq[Byte]): Boolean = if (sig.isEmpty) false
  else {
    val hashType = (sig.last & 0xff) & (~(SIGHASH_ANYONECANPAY))
    if (hashType < SIGHASH_ALL || hashType > SIGHASH_SINGLE) false else true
  }

  /**
    * An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
    *
    * @param blob sigbyte data
    * @return the decoded (r, s) signature
    */
  def decodeSignature(blob: Seq[Byte]): (BigInteger, BigInteger) = {
    val decoder = new ASN1InputStream(blob.toArray)
    val seq = decoder.readObject.asInstanceOf[DLSequence]
    val r = seq.getObjectAt(0).asInstanceOf[ASN1Integer]
    val s = seq.getObjectAt(1).asInstanceOf[ASN1Integer]
    decoder.close()
    (r.getPositiveValue, s.getPositiveValue)
  }

  def verifySignature(data: Seq[Byte], signature: (BigInteger, BigInteger), publicKey: PublicKey): Boolean = {
    val (r, s) = signature
    require(r.compareTo(one) >= 0, "r must be >= 1")
    require(r.compareTo(curve.getN) < 0, "r must be < N")
    require(s.compareTo(one) >= 0, "s must be >= 1")
    require(s.compareTo(curve.getN) < 0, "s must be < N")

    val signer = new ECDSASigner
    val params = new ECPublicKeyParameters(publicKey.value, curve)
    signer.init(false, params)
    signer.verifySignature(data.toArray, r, s)
  }

  /**
    * @param data      data
    * @param signature signature
    * @param publicKey public key
    * @return true is signature is valid for this data with this public key
    */
  def verifySignature(data: Seq[Byte], signature: Seq[Byte], publicKey: PublicKey): Boolean = verifySignature(data, decodeSignature(signature), publicKey)

  /**
    *
    * @param privateKey private key
    * @return the corresponding public key
    */
  def publicKeyFromPrivateKey(privateKey: Seq[Byte]) = Scalar(privateKey).toPoint

  /**
    * Sign data with a private key, using RCF6979 deterministic signatures
    *
    * @param data       data to sign
    * @param privateKey private key. If you are using bitcoin "compressed" private keys make sure to only use the first 32 bytes of
    *                   the key (there is an extra "1" appended to the key)
    * @return a (r, s) ECDSA signature pair
    */
  def sign(data: BinaryData, privateKey: PrivateKey): (BigInteger, BigInteger) = {
    val signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest))
    val privateKeyParameters = new ECPrivateKeyParameters(privateKey, curve)
    signer.init(true, privateKeyParameters)
    val Array(r, s) = signer.generateSignature(data.toArray)

    if (s.compareTo(halfCurveOrder) > 0) {
      (r, curve.getN().subtract(s)) // if s > N/2 then s = N - s
    } else {
      (r, s)
    }
  }
}
