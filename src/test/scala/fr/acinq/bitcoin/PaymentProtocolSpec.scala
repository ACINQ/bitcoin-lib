package fr.acinq.bitcoin

import java.io._
import java.security._
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec

import com.google.protobuf.ByteString
import org.bitcoin.protocols.payments.Protos.{Output, PaymentDetails, PaymentRequest}
import org.scalatest.{FlatSpec, Ignore}
import org.spongycastle.util.io.pem.PemReader

import scala.compat.Platform

@Ignore
class PaymentProtocolSpec extends FlatSpec {
  val keystore = KeyStore.getInstance("JKS")
  keystore.load(classOf[PaymentProtocolSpec].getResourceAsStream("/cacerts"), null)
  val aliases = keystore.aliases()

  "Payment protocol" should "verify payment requests" in {
    // to generate a test payment request I used the bitpay demo: go to https://bitpay.com/demos,
    // generate a payment, copy the payment uri and download the payment request with
    // wget --header="Accept: application/bitcoin-paymentrequest" https://bitpay.com/i/XXXXXXXXXX
    val stream = classOf[PaymentProtocolSpec].getResourceAsStream("/paymentrequest.bin")
    val request = PaymentRequest.parseFrom(stream)
    val (name, publicKey, trustAnchor) = PaymentProtocol.verifySignature(request, keystore)
    assert(name === "bitpay.com")

    // check that we get an exception if we attempt to modify payment details
    val details = PaymentDetails.parseFrom(request.getSerializedPaymentDetails)
    val request1 = request.toBuilder.setSerializedPaymentDetails(details.toBuilder.setPaymentUrl("foo").build().toByteString).build()
    intercept[RuntimeException] {
      PaymentProtocol.verifySignature(request1, keystore)
    }
  }

  it should "sign payment requests" in {
    val factory = CertificateFactory.getInstance("X.509")
    val cacert = factory.generateCertificate(classOf[PaymentProtocolSpec].getResourceAsStream("/cacert.pem")).asInstanceOf[X509Certificate]
    val servercert = factory.generateCertificate(classOf[PaymentProtocolSpec].getResourceAsStream("/servercert.pem")).asInstanceOf[X509Certificate]
    //val cert3 = factory.generateCertificate(classOf[PaymentProtocolSpec].getResourceAsStream("/ca-int2.crt")).asInstanceOf[X509Certificate]
    val keyPair = new PemReader(new InputStreamReader(classOf[PaymentProtocolSpec].getResourceAsStream("/serverkey.pem"))).readPemObject()
    val keyFactory = KeyFactory.getInstance("RSA")
    val key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getContent))
    keystore.setCertificateEntry("foo", cacert)
    val details = PaymentDetails.newBuilder()
      .addOutputs(Output.newBuilder().setAmount(100).setScript(ByteString.EMPTY))
      .setMemo("foo")
      .setPaymentUrl("")
      .setTime(Platform.currentTime)

    val request = PaymentRequest.newBuilder()
      .setPaymentDetailsVersion(1)
      .setSerializedPaymentDetails(details.build().toByteString)
      .build

    val request1 = PaymentProtocol.sign(request, Seq(servercert), key)
    val (name, publicKey, trustAnchor) = PaymentProtocol.verifySignature(request1, keystore)
    assert(name === "Foobar")
  }
}
