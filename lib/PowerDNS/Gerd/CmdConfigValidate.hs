module PowerDNS.Gerd.CmdConfigValidate
  ( runConfigValidate
  )
where

import PowerDNS.Gerd.Config (loadConfig)
import System.Exit (exitFailure, exitSuccess)
import System.IO
import UnliftIO (SomeException, displayException, handle)

runConfigValidate :: FilePath -> IO ()
runConfigValidate path = handle failure (loadConfig path >> success)
  where
    success :: IO ()
    success = do
      hPutStrLn stdout "Config valid. Good to go!"
      exitSuccess

    failure :: SomeException -> IO ()
    failure e = do
      hPutStrLn stderr "Error while loading config."
      hPutStrLn stderr (displayException e)
      exitFailure
