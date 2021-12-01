{-# OPTIONS_GHC -Wno-unused-do-bind #-}
module PowerDNS.Gerd.CmdServer
  ( runServer
  )
where

import           Network.Wai.Handler.Warp (Settings, defaultSettings,
                                           runSettings, setBeforeMainLoop,
                                           setGracefulShutdownTimeout, setHost,
                                           setInstallShutdownHandler, setPort)
import           PowerDNS.Gerd.Config
import           PowerDNS.Gerd.Options
import           PowerDNS.Gerd.Server (mkApp)
import qualified System.Posix.Signals as Posix
import           UnliftIO (TVar, atomically, newTVarIO, writeTVar)


runServer :: ServerOpts -> IO ()
runServer opts = do
    cfg <- loadConfig (optConfig opts)

    tv <- newTVarIO cfg
    Posix.installHandler Posix.sigHUP (Posix.Catch $ reloadConfig tv) Nothing

    runSettings (settings cfg) =<< mkApp (optVerbosity opts) tv
  where
    settings :: Config -> Settings
    settings cfg = setPort (fromIntegral (cfgListenPort cfg))
                 . setHost (cfgListenAddress cfg)
                 . setInstallShutdownHandler shutdownHandler
                 . setBeforeMainLoop welcome
                 . setGracefulShutdownTimeout (Just 60)
                 $ defaultSettings

    shutdownHandler closeSocket = do
      Posix.installHandler Posix.sigTERM (Posix.Catch $ goodbye >> closeSocket) Nothing
      Posix.installHandler Posix.sigINT (Posix.Catch $ goodbye >> closeSocket) Nothing
      pure ()

    welcome = putStrLn "PowerDNS-Gerd started."
    goodbye = putStrLn "Graceful shutdown requested, stopping PowerDNS-Gerd..."

    reloadConfig :: TVar Config -> IO ()
    reloadConfig tv = do
      putStrLn "Reloading config..."
      atomically . writeTVar tv =<< loadConfig (optConfig opts)
