package org.bitcoin

abstract class Secp256k1Context {
  @native def secp256k1_init_context(): Long
}

object Secp256k1Context extends Secp256k1Context {
  val (isEnabled, context): (Boolean, Long) = try {
    if ("The Android Project".equals(System.getProperty("java.vm.vendor"))) {
      System.loadLibrary("secp256k1")
    } else {
      fr.acinq.Secp256k1Loader.initialize()
    }
    (true, secp256k1_init_context())
  } catch {
    case t: Throwable => (false, -1L)
  }

  def getContext(): Long = context
}
