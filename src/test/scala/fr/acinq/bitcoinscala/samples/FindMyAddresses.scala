package fr.acinq.bitcoinscala.samples

import fr.acinq.bitcoinscala.Crypto.PublicKey
import fr.acinq.bitcoinscala.DeterministicWallet._
import fr.acinq.bitcoinscala.{Base58, Base58Check, Crypto, DeterministicWallet, MnemonicCode, Script}

object FindMyAddresses extends App {
  /**
    * this is how you can re-compute the keys and addresses used by
    * a BIP44/BIP49 compliant wallet (Copay, ....) from its seed
    */

  val mnemonics = "logic lend birth budget season code evil action review thought learn trigger deputy negative problem slice chimney sustain badge arrest ready blast kind settle"
  val passphrase = ""
  val testnet = true

  // A BIP49 wallet would use p2sh-of-p2wpkh
  def address(pub: PublicKey): String = Base58Check.encode(if (testnet) Base58.Prefix.ScriptAddressTestnet else Base58.Prefix.ScriptAddress, Crypto.hash160(Script.write(Script.pay2wpkh(pub))))

  // step #1: compute the seed from the mnemonic code
  val seed = MnemonicCode.toSeed(mnemonics, passphrase)

  // step #2: generate the master key from the seed
  val master = generate(seed)
  println(s"master key: $master ${encode(master, if (testnet) tprv else xprv)} ${encode(publicKey(master), if (testnet) tpub else xpub)}")

  // step #3: derive the account key from the master key
  val account = derivePrivateKey(master, hardened(49) :: hardened(if (testnet) 1 else 0) :: hardened(0) :: Nil)

  val accountPub = publicKey(account)
  println(s"account public key: $accountPub ${encode(accountPub, if (testnet) tpub else xpub)}")

  // compute a few keys and addresses...
  for (i <- 0L to 10L) {
    val pub = DeterministicWallet.publicKey(DeterministicWallet.derivePrivateKey(account, 0L :: i :: Nil))
    println(address(pub.publicKey))
  }
}
