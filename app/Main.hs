module Main where

import PowerDNS.Guard.Server (mkApp)
import PowerDNS.Guard.Config (loadConfig, Config(..), configHelp)
import Network.Wai.Handler.Warp (Settings, setPort, setHost, defaultSettings, runSettings)
import System.IO (hSetBuffering, BufferMode(..), stderr, stdout)
import PowerDNS.Guard.Options (getCommand, Command(..), ServerOpts(..))
import System.Environment (getArgs)
import System.Exit (exitSuccess)

setBuffering :: IO ()
setBuffering = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering

main :: IO ()
main = do
  setBuffering 
  runCommand =<< getCommand =<< getArgs

runCommand :: Command -> IO ()
runCommand CmdConfigHelp = putStrLn configHelp >> exitSuccess
runCommand (CmdRunServer opts) = runServer opts

runServer :: ServerOpts -> IO ()
runServer opts = do
  cfg <- loadConfig (optConfig opts)
  runSettings (mkSettings cfg) =<< mkApp cfg

mkSettings :: Config -> Settings
mkSettings cfg = setPort (fromIntegral (cfgListenPort cfg))
               . setHost (cfgListenAddress cfg)
               $ defaultSettings
