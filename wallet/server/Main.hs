module Main where

import           Universum

import           Pos.Client.CLI (NodeArgs (..), loggingParams)
import           Pos.Launcher (launchNode)
import           Pos.Util.CompileInfo (withCompileInfo)

import           Cardano.Wallet.Action (actionWithWallet)
import Cardano.Wallet.Kernel.Transactions
import           Cardano.Wallet.Server.CLI (WalletStartupOptions (..), getWalletNodeOptions)

import Pos.Core.NetworkMagic
import Pos.Crypto.HD
import Pos.Crypto.Hashing
import Pos.Chain.Txp
import Pos.Binary.Class
import Pos.Crypto.Signing
import Pos.Crypto.Configuration
import Pos.Core.Common
import Pos.Core.Attributes

import qualified Data.ByteString as B8
import qualified Cardano.Crypto.Wallet as CC
import qualified Data.ByteString.Lazy as BL
import qualified Data.List.NonEmpty as NE
import qualified Data.ByteString as BS

main :: IO ()
main = do
    (addr, signedTx) <-
        test
            (NetworkTestnet 1097911063)
            (ProtocolMagic (ProtocolMagicId 1097911063) RequiresMagic)

    BL.writeFile "goldens/testnet/sl-addr.bin" addr
    BL.writeFile "goldens/testnet/sl-signedTx.bin" signedTx

    (mainnetAddr, mainnetSignedTx) <-
        test
            NetworkMainOrStage
            (ProtocolMagic (ProtocolMagicId 764824073) RequiresMagic)

    BL.writeFile "goldens/mainnet/sl-addr.bin" mainnetAddr
    BL.writeFile "goldens/mainnet/sl-signedTx.bin" mainnetSignedTx

test :: NetworkMagic -> ProtocolMagic -> IO (BL.ByteString, BL.ByteString)
test nm pm = do

    let pass = PassPhrase mempty
    let gen = mempty :: BS.ByteString
    let seed = (BS.pack $ replicate 128 0)

    let xprv = CC.generateNew seed gen pass
    esk <- mkEncSecretUnsafe pass xprv


    let addrXPub = encToPublic esk
    let addr = makePubKeyAddressBoot nm addrXPub

    let signer = SafeSigner esk pass
    let shuffle = return -- Don't shuffle outputs

    -- Construct a simple tx:
    let inp = ( TxInUtxo (unsafeHash @String "faucetTx") 0
              , TxOutAux $ TxOut addr (Coin 1)
              )
    res <- mkStdTx pm shuffle (const $ Right signer) (NE.fromList [inp]) (NE.fromList [snd inp]) []
    let signedTx = fromR res

    let attrs = mkAttributes ()
    let tx = UnsafeTx (NE.fromList [fst inp]) (NE.fromList [toaOut $ snd inp]) attrs

    return
        ( (toLazyByteString $ encode addr)
        , (toLazyByteString $ encode signedTx)
        )
  where
    fromR = either (error "Unexpected left") id


