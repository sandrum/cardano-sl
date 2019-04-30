module Main where

--  build-depends:
--      base
--      bytestring
--      cardano-crypto
--      cardano-sl
--      cardano-sl-binary
--      cardano-sl-chain
--      cardano-sl-core
--      cardano-sl-crypto
--      cardano-wallet
--      containers
--      memory
--      universum

import           Universum

import           Cardano.Wallet.Kernel.Transactions (mkStdTx)

import           Pos.Binary.Class
import           Pos.Chain.Txp
import           Pos.Core.Common
import           Pos.Core.NetworkMagic
import           Pos.Crypto.Configuration
import           Pos.Crypto.Hashing
import           Pos.Crypto.Signing

import           System.IO.Unsafe (unsafePerformIO)

import qualified Cardano.Crypto.Wallet as CC
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import qualified Data.List.NonEmpty as NE
import qualified Data.Map.Strict as Map

main :: IO ()
main = do
    genGoldenTest mainnet 1
        [ (genESK "addr-0", Coin 42) ]

    genGoldenTest mainnet 2
        [ (genESK "addr-0", Coin 42)
        , (genESK "addr-1", Coin 14) ]

    genGoldenTest mainnet 25
        [ (genESK "addr-0", Coin 14) ]

    genGoldenTest mainnet 1
        [ (genESK "addr-0", Coin 14)
        , (genESK "addr-1", Coin 42)
        , (genESK "addr-2", Coin 287)
        , (genESK "addr-3", Coin 647)
        , (genESK "addr-4", Coin 1145)
        , (genESK "addr-5", Coin 2178)
        , (genESK "addr-6", Coin 6874)
        , (genESK "addr-7", Coin 9177)
        , (genESK "addr-8", Coin 21412)
        , (genESK "addr-9", Coin 35787)
        , (genESK "addr-10", Coin 66745)
        , (genESK "addr-11", Coin 142141)
        , (genESK "addr-12", Coin 314142)
        , (genESK "addr-13", Coin 666666)
        , (genESK "addr-14", Coin 1389571)
        , (genESK "addr-15", Coin 8589934592)
        , (genESK "addr-16", Coin 1)
        , (genESK "addr-17", Coin 1)
        , (genESK "addr-18", Coin 1)
        , (genESK "addr-19", Coin 1)
        , (genESK "addr-20", Coin 1)
        , (genESK "addr-21", Coin 1)
        , (genESK "addr-22", Coin 1)
        , (genESK "addr-23", Coin 1)
        , (genESK "addr-24", Coin 1)
        , (genESK "addr-25", Coin 1) ]

    genGoldenTest testnet 1
        [ (genESK "addr-0", Coin 42) ]

    genGoldenTest testnet 2
        [ (genESK "addr-0", Coin 42)
        , (genESK "addr-1", Coin 14) ]

    genGoldenTest testnet 25
        [ (genESK "addr-0", Coin 14) ]

    genGoldenTest testnet 1
        [ (genESK "addr-0", Coin 14)
        , (genESK "addr-1", Coin 42)
        , (genESK "addr-2", Coin 287)
        , (genESK "addr-3", Coin 647)
        , (genESK "addr-4", Coin 1145)
        , (genESK "addr-5", Coin 2178)
        , (genESK "addr-6", Coin 6874)
        , (genESK "addr-7", Coin 9177)
        , (genESK "addr-8", Coin 21412)
        , (genESK "addr-9", Coin 35787)
        , (genESK "addr-10", Coin 66745)
        , (genESK "addr-11", Coin 142141)
        , (genESK "addr-12", Coin 314142)
        , (genESK "addr-13", Coin 666666)
        , (genESK "addr-14", Coin 1389571)
        , (genESK "addr-15", Coin 8589934592)
        , (genESK "addr-16", Coin 1)
        , (genESK "addr-17", Coin 1)
        , (genESK "addr-18", Coin 1)
        , (genESK "addr-19", Coin 1)
        , (genESK "addr-20", Coin 1)
        , (genESK "addr-21", Coin 1)
        , (genESK "addr-22", Coin 1)
        , (genESK "addr-23", Coin 1)
        , (genESK "addr-24", Coin 1)
        , (genESK "addr-25", Coin 1) ]
  where
    testnet =
        ( NetworkTestnet 1097911063
        , ProtocolMagic (ProtocolMagicId 1097911063) RequiresMagic
        )
    mainnet =
        ( NetworkMainOrStage
        , ProtocolMagic (ProtocolMagicId 764824073) RequiresMagic
        )

-- | Generate an encrypted key from a seed, with an empty passphrase
genESK
    :: ByteString
    -> EncryptedSecretKey
genESK seed = unsafePerformIO $
    mkEncSecretUnsafe mempty (CC.generateNew seed pwd pwd)
  where
    pwd :: ByteString
    pwd = mempty

-- | Generate a golden test containing a signed transaction
genGoldenTest
    :: (NetworkMagic, ProtocolMagic)
        -- ^ Protocol parameters
    -> Int
        -- ^ Number of outputs
    -> [(EncryptedSecretKey, Coin)]
        -- ^ (Address Private Keys, Output value)
    -> IO ()
genGoldenTest (nm, pm) nOuts xprvs = do
    let addrs = first (makePubKeyAddressBoot nm . encToPublic) <$> xprvs
    let res = mkStdTx pm shuffler signer inps outs []
          where
            shuffler = return
            signer addr = maybe
                (Left ()) (\(esk,_) -> Right $ SafeSigner esk mempty) (Map.lookup addr m)
              where
                m = Map.fromList (zip (fst <$> addrs) xprvs)
            inps = NE.fromList $ mkInput <$> zip [0..] addrs
            outs = NE.fromList $ take nOuts $ mkOutput <$> (cycle addrs)
    case res of
        Left _ -> fail $ "genGoldenTest: failed to sign tx"
        Right tx -> do
            let bytes = toLazyByteString $ encode tx
            B8.putStrLn $
                B8.pack (show nm)
                <> " " <> show nOuts <> " ouputs"
                <> " " <> show (length xprvs) <> " inputs"
            print $ (B8.unpack . addrToBase58 . fst) <$> addrs
            -- NOTE Dropping first 4 bytes of 'TxAux' wrapper, not actually
            -- present on chain.
            B8.putStrLn $ BS.drop 4 $ BA.convertToBase BA.Base16 $ BL.toStrict bytes
            B8.putStrLn ""
  where
    mkInput (ix, addr) =
        let
            txId = unsafeHash @String "arbitrary"
        in
            ( TxInUtxo txId ix
            , mkOutput addr
            )
    mkOutput (addr, c) =
        TxOutAux $ TxOut addr c
