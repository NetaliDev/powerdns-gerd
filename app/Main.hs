module Main where

import System.Environment (getArgs)
import System.IO (BufferMode(..), hSetBuffering, stderr, stdout)

import Network.Wai.Handler.Warp (Settings, defaultSettings, runSettings,
                                 setHost, setPort)

import PowerDNS.Gerd.CmdConfig
import PowerDNS.Gerd.CmdDigest
import PowerDNS.Gerd.CmdVersion

import PowerDNS.Gerd.Config (Config(..), loadConfig)
import PowerDNS.Gerd.Options (Command(..), ServerOpts(..), getCommand)
import PowerDNS.Gerd.Server (mkApp)

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
runCommand (CmdRunServer opts)      = runServer opts
runCommand (CmdDigest opts)         = runDigest opts

runServer :: ServerOpts -> IO ()
runServer opts = do
  cfg <- loadConfig (optConfig opts)
  runSettings (mkSettings cfg) =<< mkApp (optVerbosity opts) cfg

mkSettings :: Config -> Settings
mkSettings cfg = setPort (fromIntegral (cfgListenPort cfg))
               . setHost (cfgListenAddress cfg)
               $ defaultSettings
