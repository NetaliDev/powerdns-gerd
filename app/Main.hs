module Main where

import Control.Exception
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (BufferMode(..), hPutStrLn, hSetBuffering, stderr, stdout)

import PowerDNS.Gerd.CmdConfig
import PowerDNS.Gerd.CmdDigest
import PowerDNS.Gerd.CmdServer
import PowerDNS.Gerd.CmdVersion

import PowerDNS.Gerd.Options (Command(..), getCommand)

setBuffering :: IO ()
setBuffering = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering

main :: IO ()
main = handle uncaught $ do
    setBuffering
    runCommand =<< getCommand =<< getArgs

  where
    uncaught :: SomeException -> IO a
    uncaught ex = do
      hPutStrLn stderr (displayException ex)
      exitFailure

runCommand :: Command -> IO ()
runCommand CmdVersion               = runVersion
runCommand CmdConfigHelp            = runConfigHelp
runCommand (CmdConfigValidate path) = runConfigValidate path
runCommand (CmdServer opts)         = runServer opts
runCommand (CmdDigest opts)         = runDigest opts
