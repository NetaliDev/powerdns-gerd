-- |
-- Module: PowerDNS.Gerd.User
-- Description: Authorization for users
--
-- This module implements the cryptographic authentication of users
--
module PowerDNS.Gerd.User
  ( User(..)
  , Username(..)
  , Credential(..)
  , Authenticated(..)
  , authenticate
  , verifyArgon2id
  , module PowerDNS.Gerd.User.Types
  )
where

import           Control.Monad.IO.Class (MonadIO, liftIO)

import qualified Data.ByteString.Char8 as B8
import           Foreign.Ptr (castPtr)
import           Libsodium

import           PowerDNS.Gerd.User.Types

data Authenticated = Authenticated
  deriving (Show, Eq)

authenticate :: (MonadIO m) => User -> B8.ByteString -> m (Maybe Authenticated)
authenticate user pass = case uCredential user of
  CredHash hash -> verifyArgon2id pass hash
  CredPSK psk   -> verifyPSK pass psk

verifyPSK :: MonadIO m => B8.ByteString -> B8.ByteString -> m (Maybe Authenticated)
verifyPSK pskL pskR | lenL /= lenR = pure Nothing
                    | otherwise = liftIO $
        B8.useAsCString pskL $ \lbuf ->
            B8.useAsCString pskR $ \rbuf -> do
            res <- sodium_compare (castPtr lbuf) (castPtr rbuf) (fromIntegral lenR)
            case res of
                0 -> pure (Just Authenticated)
                _ -> pure Nothing
  where
    lenL = B8.length pskL
    lenR = B8.length pskR

verifyArgon2id :: MonadIO m => B8.ByteString -> B8.ByteString -> m (Maybe Authenticated)
verifyArgon2id pass hash = liftIO $
  B8.useAsCString pass $ \p ->
    B8.useAsCString hash $ \h -> do
      res <- crypto_pwhash_argon2id_str_verify h p (fromIntegral (B8.length pass))
      case res of
        0 -> pure (Just Authenticated)
        _ -> pure Nothing
