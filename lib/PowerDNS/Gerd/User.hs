-- |
-- Module: PowerDNS.Gerd.User
-- Description: Authorization for users
--
-- This module implements the cryptographic authentication of users
--
module PowerDNS.Gerd.User
  ( User(..)
  , Username(..)
  , authenticate
  , module PowerDNS.Gerd.User.Types
  )
where


import qualified Data.ByteString.Char8 as B8
import           Libsodium

import           PowerDNS.Gerd.User.Types

authenticate :: User -> B8.ByteString -> IO Bool
authenticate user pass = verifyArgon2id pass (uPassHash user)

verifyArgon2id :: B8.ByteString -> B8.ByteString -> IO Bool
verifyArgon2id pass hash =
  B8.useAsCString pass $ \p ->
    B8.useAsCString hash $ \h -> do
      res <- crypto_pwhash_argon2id_str_verify h p (fromIntegral (B8.length pass))
      case res of
        0 -> pure True
        _ -> pure False
