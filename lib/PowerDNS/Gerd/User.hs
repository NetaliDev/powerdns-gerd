module PowerDNS.Gerd.User
  ( User(..)
  , Username(..)
  , authenticate
  , module PowerDNS.Gerd.User.Types
  )
where


import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T
import           Libsodium

import           PowerDNS.Gerd.User.Types

authenticate :: [(Username, User)] -> T.Text -> B8.ByteString -> IO (Maybe User)
authenticate db name pass = maybe (pure Nothing)
                                  verify
                                  (lookup (Username name) db)
  where
    verify :: User -> IO (Maybe User)
    verify ac = do
      valid <- verifyArgon2id pass (uPassHash ac)
      if valid
        then pure (Just ac)
        else pure Nothing

verifyArgon2id :: B8.ByteString -> B8.ByteString -> IO Bool
verifyArgon2id pass hash =
  B8.useAsCString pass $ \p ->
    B8.useAsCString hash $ \h -> do
      res <- crypto_pwhash_argon2id_str_verify h p (fromIntegral (B8.length pass))
      case res of
        0 -> pure True
        _ -> pure False
