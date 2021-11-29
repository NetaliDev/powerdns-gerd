module Main where

import System.Environment (getArgs)
import System.IO (BufferMode(..), hSetBuffering, stderr, stdout)

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
main = do
  setBuffering
  runCommand =<< getCommand =<< getArgs

runCommand :: Command -> IO ()
runCommand CmdVersion               = runVersion
runCommand CmdConfigHelp            = runConfigHelp
runCommand (CmdConfigValidate path) = runConfigValidate path
runCommand (CmdServer opts)         = runServer opts
runCommand (CmdDigest opts)         = runDigest opts
