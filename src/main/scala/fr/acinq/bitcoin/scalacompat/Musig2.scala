package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin.ScriptTree
import fr.acinq.bitcoin.crypto.musig2.{IndividualNonce, SecretNonce}
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey, XonlyPublicKey}
import fr.acinq.bitcoin.scalacompat.KotlinUtils._

import scala.jdk.CollectionConverters.SeqHasAsJava

object Musig2 {

  /**
   * Aggregate the public keys of a musig2 session into a single public key.
   * Note that this function doesn't apply any tweak: when used for taproot, it computes the internal public key, not
   * the public key exposed in the script (which is tweaked with the script tree).
   *
   * @param publicKeys public keys of all participants: callers must verify that all public keys are valid.
   */
  def aggregateKeys(publicKeys: Seq[PublicKey]): XonlyPublicKey = XonlyPublicKey(fr.acinq.bitcoin.crypto.musig2.Musig2.aggregateKeys(publicKeys.map(scala2kmp).asJava))

  /**
   * @param sessionId  a random, unique session ID.
   * @param privateKey signer's private key
   * @param publicKey  signer's public key
   * @param publicKeys public keys of all participants: callers must verify that all public keys are valid.
   * @param message    (optional) message that will be signed, if already known.
   * @param extraInput (optional) additional random data.
   */
  def generateNonce(sessionId: ByteVector32, privateKey: Option[PrivateKey], publicKey: PublicKey, publicKeys: Seq[PublicKey], message: Option[ByteVector32], extraInput: Option[ByteVector32]): (SecretNonce, IndividualNonce) = {
    val nonce = fr.acinq.bitcoin.crypto.musig2.Musig2.generateNonce(sessionId, privateKey.map(scala2kmp).orNull, publicKey, publicKeys.map(scala2kmp).asJava, message.map(scala2kmp).orNull, extraInput.map(scala2kmp).orNull)
    (nonce.getFirst, nonce.getSecond)
  }

  /**
   * @param nonRepeatingCounter non-repeating counter that must never be reused with the same private key.
   * @param privateKey          signer's private key.
   * @param publicKeys          public keys of all participants: callers must verify that all public keys are valid.
   * @param message             (optional) message that will be signed, if already known.
   * @param extraInput          (optional) additional random data.
   */
  def generateNonceWithCounter(nonRepeatingCounter: Long, privateKey: PrivateKey, publicKeys: Seq[PublicKey], message: Option[ByteVector32], extraInput: Option[ByteVector32]): (SecretNonce, IndividualNonce) = {
    val nonce = fr.acinq.bitcoin.crypto.musig2.Musig2.generateNonceWithCounter(nonRepeatingCounter, privateKey, publicKeys.map(scala2kmp).asJava, message.map(scala2kmp).orNull, extraInput.map(scala2kmp).orNull)
    (nonce.getFirst, nonce.getSecond)
  }

  /**
   * Create a partial musig2 signature for the given taproot input key path.
   *
   * @param privateKey     private key of the signing participant.
   * @param tx             transaction spending the target taproot input.
   * @param inputIndex     index of the taproot input to spend.
   * @param inputs         all inputs of the spending transaction.
   * @param publicKeys     public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
   * @param secretNonce    secret nonce of the signing participant.
   * @param publicNonces   public nonces of all participants of the musig2 session.
   * @param scriptTree_opt tapscript tree of the taproot input, if it has script paths.
   */
  def signTaprootInput(privateKey: PrivateKey, tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], publicKeys: Seq[PublicKey], secretNonce: SecretNonce, publicNonces: Seq[IndividualNonce], scriptTree_opt: Option[ScriptTree]): Either[Throwable, ByteVector32] = {
    fr.acinq.bitcoin.crypto.musig2.Musig2.signTaprootInput(privateKey, tx, inputIndex, inputs.map(scala2kmp).asJava, publicKeys.map(scala2kmp).asJava, secretNonce, publicNonces.asJava, scriptTree_opt.orNull).map(kmp2scala)
  }

  /**
   * Verify a partial musig2 signature.
   *
   * @param partialSig     partial musig2 signature.
   * @param nonce          public nonce matching the secret nonce used to generate the signature.
   * @param publicKey      public key for the private key used to generate the signature.
   * @param tx             transaction spending the target taproot input.
   * @param inputIndex     index of the taproot input to spend.
   * @param inputs         all inputs of the spending transaction.
   * @param publicKeys     public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
   * @param publicNonces   public nonces of all participants of the musig2 session.
   * @param scriptTree_opt tapscript tree of the taproot input, if it has script paths.
   * @return true if the partial signature is valid.
   */
  def verifyTaprootSignature(partialSig: ByteVector32, nonce: IndividualNonce, publicKey: PublicKey, tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], publicKeys: Seq[PublicKey], publicNonces: Seq[IndividualNonce], scriptTree_opt: Option[ScriptTree]): Boolean = {
    fr.acinq.bitcoin.crypto.musig2.Musig2.verify(partialSig, nonce, publicKey, tx, inputIndex, inputs.map(scala2kmp).asJava, publicKeys.map(scala2kmp).asJava, publicNonces.asJava, scriptTree_opt.orNull)
  }

  /**
   * Aggregate partial musig2 signatures into a valid schnorr signature for the given taproot input key path.
   *
   * @param partialSigs    partial musig2 signatures of all participants of the musig2 session.
   * @param tx             transaction spending the target taproot input.
   * @param inputIndex     index of the taproot input to spend.
   * @param inputs         all inputs of the spending transaction.
   * @param publicKeys     public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
   * @param publicNonces   public nonces of all participants of the musig2 session.
   * @param scriptTree_opt tapscript tree of the taproot input, if it has script paths.
   */
  def aggregateTaprootSignatures(partialSigs: Seq[ByteVector32], tx: Transaction, inputIndex: Int, inputs: Seq[TxOut], publicKeys: Seq[PublicKey], publicNonces: Seq[IndividualNonce], scriptTree_opt: Option[ScriptTree]): Either[Throwable, ByteVector64] = {
    fr.acinq.bitcoin.crypto.musig2.Musig2.aggregateTaprootSignatures(partialSigs.map(scala2kmp).asJava, tx, inputIndex, inputs.map(scala2kmp).asJava, publicKeys.map(scala2kmp).asJava, publicNonces.asJava, scriptTree_opt.orNull).map(kmp2scala)
  }

}
