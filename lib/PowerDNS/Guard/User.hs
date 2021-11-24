module PowerDNS.Guard.User
  ( User(..)
  , authenticate
  )
where


import qualified Data.Text as T
import Libsodium
import qualified Data.ByteString.Char8 as B8
import Data.Foldable (find)

import PowerDNS.Guard.User.Types

authenticate :: [User] -> T.Text -> B8.ByteString -> IO (Maybe User)
authenticate db name pass = maybe (pure Nothing)
                                  verify
                                  (find matchingName db)
  where
    matchingName :: User -> Bool
    matchingName ac = _uName ac == name
  
    verify :: User -> IO (Maybe User)
    verify ac = do
      valid <- verifyArgon2id pass (_uPassHash ac)
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

