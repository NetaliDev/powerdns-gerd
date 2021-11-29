module PowerDNS.Gerd.CmdConfig
  ( runConfigValidate
  , runConfigHelp
  )
where

import PowerDNS.Gerd.Config (configHelp, loadConfig)
import System.Exit (exitFailure, exitSuccess)
import System.IO
import UnliftIO (SomeException, displayException, handle)

runConfigHelp :: IO ()
runConfigHelp = do
  putStrLn configHelp
  exitSuccess

runConfigValidate :: FilePath -> IO ()
runConfigValidate path = handle failure (() <$ loadConfig path) >> success
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
