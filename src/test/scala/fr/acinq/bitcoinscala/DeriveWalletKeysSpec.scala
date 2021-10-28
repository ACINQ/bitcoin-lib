package fr.acinq.bitcoinscala

import org.scalatest.FunSuite

/**
  * check that we can restore BIP44, BIP49 and BIP84 wallets and generate valid xpubs and addresses.
  * please note that this test only shows how to derive account keys and addresses. Change keys and addresses can
  * use the same scheme will a different derivation path.
  * this was tested with electrum (BIPs 44, 49, 84) and mycellium (BIP44) testnet wallets
  */
class DeriveWalletKeysSpec extends FunSuite {

  import DeriveWalletKeysSpec._

  val mnemonics = "gun please vital unable phone catalog explain raise erosion zoo truly exist"
  val seed = MnemonicCode.toSeed(mnemonics, "")
  val master = DeterministicWallet.generate(seed)

  test("restore BIP44 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/44'/1'/0'"))
    // some wallets will use tpub instead of upub
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.tpub)
    assert(xpub == "tpubDDamug2qVwe94yFJ38MM3ek2LiWiyjMmkQPhYMnHNZz5XHj7bj8xc7pFmyiYnCfqrSy62e1196qcpmKYhcUMcBTGMW4mEWf1v9H8wNtLZku")
    assert(deriveAddresses(xpub, Some(BIP44)) == Seq("mmpDgTP9FQbJCcdkkuXLbjbvqg3j33Zw3H", "mtXgQHM7Eawr6rjDWh7CrFtBQnbibviekL", "mw39H2JNixLuXLfTXqZr53M1n18ekPNi9U", "mnK3W3DMnkKMPT3Kbx6gvrmWxch6BhNHoo", "mpotVZLVr3fgbuBD2jzmwxVg7iATpq7YME"))
  }

  test("restore BIP49 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/49'/1'/0'"))
    // some wallets will use tpub instead of upub
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.upub)
    assert(xpub == "upub5DKk7kdrLoL3HqrfVdf3mLZJ59g6Bix8UtB6YJQNSKfE3E6YU2Vq7dH7E8ce87jUAac4nRag6Zd7c2cXs45Q4nJcLdrJyNWPxS5D9LFSpGL")
    assert(deriveAddresses(xpub) == Seq("2NAV38YdZBS6s6b89QdmyPnjBxn6Jn3BkhQ", "2Mzxym6Rey5Mwnnxh6L134MaHFwTPQB4fdx", "2N8tTGMc57REfePZzPkWqEGaYKHsrVsW3LJ", "2Mxfuivcx4TdGroh6Q2GmCR5rQB46fjJUtn", "2N7uWEqMPCjzHynqSDaAnydZD6WfEpH9ekz"))
  }

  test("restore BIP84 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/84'/1'/0'"))
    // some wallets will use tpub instead of upub
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.vpub)
    assert(xpub == "vpub5YmxxDXhaEfLoqxn8xJExGMSQepxRbJDFqyc9FpDKyW8z966eDsgqbTHnJCvc698MhN3FDRt49DuPBgdRufopecaeyffJCUKXRKHoNn7BhX")
    assert(deriveAddresses(xpub) == Seq("tb1ql63el50rtln6n4kxa76jrhuts3kxmk9wtz6hp0", "tb1qa2hyhca4y07xqcl9r9m63rtv4hgdh063hldn6r", "tb1q0lywyl3cdkuw29yuh6w0frqh4hnxdj0m4e78eq", "tb1q4dg72vn06mrjh3yyzpkws3w2z0whrys8g2a997", "tb1qx4g3glhflr42clkkla9ty0vmfcmme9a426mrc2"))
  }
}

object DeriveWalletKeysSpec {

  trait DerivationScheme

  object BIP44 extends DerivationScheme

  object BIP49 extends DerivationScheme

  object BIP84 extends DerivationScheme

  def deriveAddresses(xpub: String, derivationScheme: Option[DerivationScheme] = None) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    for (i <- 0L until 5L) yield {
      val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
      val address = prefix match {
        case DeterministicWallet.tpub if derivationScheme == Some(BIP44) => computeBIP44Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
        case DeterministicWallet.tpub if derivationScheme == Some(BIP49) => computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
        case DeterministicWallet.upub => computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
        case DeterministicWallet.vpub => computeBIP84Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
        case DeterministicWallet.xpub if derivationScheme == Some(BIP44) => computeBIP44Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
        case DeterministicWallet.xpub if derivationScheme == Some(BIP49) => computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
        case DeterministicWallet.ypub => computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
        case DeterministicWallet.zpub => computeBIP84Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
      }
      address
    }
  }
}
