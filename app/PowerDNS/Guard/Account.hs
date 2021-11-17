module PowerDNS.Guard.Account
  ( Account(..)
  , authenticate
  )
where


import qualified Data.Text as T
import Libsodium
import qualified Data.ByteString.Char8 as B8
import Servant (errBody)
import qualified Data.Text.Encoding as T
import Data.Foldable (find)

data Account = Account
  { acName :: T.Text
  , acHash :: B8.ByteString
  , acMayListZones :: Bool
  }

authenticate :: [Account] -> T.Text -> B8.ByteString -> IO (Maybe Account)
authenticate db name pass = maybe (pure Nothing)
                                  verify
                                  (find matchingName db)
  where
    matchingName :: Account -> Bool
    matchingName ac = acName ac == name
  
    verify :: Account -> IO (Maybe Account)
    verify ac = do
      valid <- verifyArgon2id pass (acHash ac)
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

