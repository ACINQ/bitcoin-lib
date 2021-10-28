package fr.acinq.bitcoinscala.samples

import fr.acinq.bitcoinscala._

object KeysFromXpub extends App {
  /**
    * this is how you would derive pubkeys and addresses from an xpub that someone gave you
    * we currently support BIP49 (p2sh-of-p2wpkh) and BIP84 (p2wpkh)
    *
    */

  def deriveAddresses(xpub: String) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    prefix match {
      case DeterministicWallet.ypub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
          println(s"$pub $address")
        }
      case DeterministicWallet.vpub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = computeBIP84Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
          println(s"$pub $address")
        }
    }
  }

  deriveAddresses("ypub6XKCLnXy5uuK5w5mL6viWaRPKJ9EQ7bo2sL4NTJ1wp6WgQp5fCEGYV5KSfF5DLDdCgUZdHBHQmTx95wfCM5LnRHQhWocNybZDhMaiytoD8J")
  deriveAddresses("vpub5V8AVGVJD4oTKnAEjjTXUg6pao1jpyooD7VwbrHdMPPcL5RvtPrdiWqtRBj5W9gbccoo8mZznYFY6QSL2CXP75eAPoRjgS6bZehQaWMoy5y")
}
