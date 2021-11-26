module Main where

import System.Environment (getArgs)
import System.Exit (exitSuccess)
import System.IO (BufferMode(..), hSetBuffering, stderr, stdout)

import Network.Wai.Handler.Warp (Settings, defaultSettings, runSettings,
                                 setHost, setPort)

import PowerDNS.Guard.Config (Config(..), configHelp, loadConfig)
import PowerDNS.Guard.Options (Command(..), ServerOpts(..), getCommand)
import PowerDNS.Guard.Server (mkApp)
import PowerDNS.Guard.Utils (ourVersion)

setBuffering :: IO ()
setBuffering = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering

main :: IO ()
main = do
  setBuffering
  runCommand =<< getCommand =<< getArgs

runCommand :: Command -> IO ()
runCommand CmdVersion          = putStrLn ourVersion >> exitSuccess
runCommand CmdConfigHelp       = putStrLn configHelp >> exitSuccess
runCommand (CmdRunServer opts) = runServer opts

runServer :: ServerOpts -> IO ()
runServer opts = do
  cfg <- loadConfig (optConfig opts)
  runSettings (mkSettings cfg) =<< mkApp (optVerbosity opts) cfg

mkSettings :: Config -> Settings
mkSettings cfg = setPort (fromIntegral (cfgListenPort cfg))
               . setHost (cfgListenAddress cfg)
               $ defaultSettings
