module PowerDNS.Gerd.CmdDigest
  ( runDigest
  )
where

import           Control.Monad (when)

import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Char8 as BS8
import           Foreign (allocaBytes)
import           Foreign.C (CSize, CULLong)
import           Libsodium
import           PowerDNS.Gerd.Options
import           PowerDNS.Gerd.User.Types
import           System.IO (hFlush, hGetEcho, hSetEcho, stdin)
import           UnliftIO (bracket_, stdout)


digest :: OpsLimit -> MemLimit -> BS8.ByteString -> IO BS8.ByteString
digest ops mem pass = BS8.useAsCStringLen pass $ \(pass', passLen) -> do
     allocaBytes (fromIntegral crypto_pwhash_strbytes) $ \outBuf -> do
       res <- crypto_pwhash_str outBuf
                                pass'
                                (fromIntegral passLen)
                                (olToCULLong ops)
                                (mlToCSize mem)
       when (res /= 0) (fail ("digest failed: " <> show res))
       BS8.packCString outBuf
  where
    olToCULLong :: OpsLimit -> CULLong
    olToCULLong OpsMin = fromIntegral crypto_pwhash_argon2id_opslimit_min
    olToCULLong OpsInteractive = fromIntegral crypto_pwhash_argon2id_opslimit_interactive
    olToCULLong OpsModerate = fromIntegral crypto_pwhash_argon2id_opslimit_moderate
    olToCULLong OpsSensitive = fromIntegral crypto_pwhash_argon2id_opslimit_sensitive
    olToCULLong OpsMax = fromIntegral crypto_pwhash_argon2id_opslimit_max

    mlToCSize :: MemLimit -> CSize
    mlToCSize MemMin         = crypto_pwhash_argon2id_memlimit_min
    mlToCSize MemInteractive = crypto_pwhash_argon2id_memlimit_interactive
    mlToCSize MemModerate    = crypto_pwhash_argon2id_memlimit_moderate
    mlToCSize MemSensitive   = crypto_pwhash_argon2id_memlimit_sensitive
    mlToCSize MemMax         = crypto_pwhash_argon2id_memlimit_max


runDigest :: DigestOpts -> IO ()
runDigest opts = do
  putStr "Password> "
  pass <- getPassword

  let pass' = BS8.pack pass

  digested <- digest (doOpsLimit opts) (doMemLimit opts) pass'
  BS.putStrLn digested

getPassword :: IO String
getPassword = do
  hFlush stdout
  pass <- withEcho False getLine
  putChar '\n'

  return pass

withEcho :: Bool -> IO a -> IO a
withEcho echo action = do
  old <- hGetEcho stdin
  bracket_ (hSetEcho stdin echo) (hSetEcho stdin old) action
