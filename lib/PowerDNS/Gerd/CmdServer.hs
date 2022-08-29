-- |
-- Module: PowerDNS.Gerd.CmdServer
-- Description: Server Command
--
-- This module defines the implementation of the @server@ subcommand of powerdns-gerd.
--
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Gerd.CmdServer
  ( runServer
  )
where

import           Control.Monad.Logger (logErrorN, logInfoN)
import qualified Data.Text as T
import           Network.Wai.Handler.Warp (defaultSettings, runSettings,
                                           setBeforeMainLoop,
                                           setGracefulShutdownTimeout, setHost,
                                           setInstallShutdownHandler, setPort)

import           System.Exit (exitFailure)

import           PowerDNS.Gerd.Config
import           PowerDNS.Gerd.Options
import           PowerDNS.Gerd.Server (mkApp)
import           PowerDNS.Gerd.Types (IOL)
import           PowerDNS.Gerd.Utils (includeTid, runLog)
import qualified System.Posix.Signals as Posix
import           UnliftIO (UnliftIO(..), askUnliftIO, liftIO)
import           UnliftIO.Exception (SomeException, catch, displayException)
import           UnliftIO.STM (TVar, atomically, newTVarIO, writeTVar)


runServer :: ServerOpts -> IO ()
runServer opts = runLog (optVerbosity opts) (runServerLogged opts)

configErr :: SomeException -> IOL a
configErr ex = do
  logErrorN ("Exception while loading config: \n" <> T.pack (displayException ex))
  liftIO exitFailure

runServerLogged :: ServerOpts -> IOL ()
runServerLogged opts = do
    UnliftIO io <- askUnliftIO

    cfg <- loadConfig (optConfig opts) `catch` configErr

    tv <- newTVarIO cfg
    liftIO $ Posix.installHandler Posix.sigHUP (Posix.Catch $ io (reloadConfig tv)) Nothing

    let settings = setPort (fromIntegral (cfgListenPort cfg))
                 . setHost (cfgListenAddress cfg)
                 . setInstallShutdownHandler (shutdownHandler io)
                 . setBeforeMainLoop (io welcome)
                 . setGracefulShutdownTimeout (Just 60)
                 $ defaultSettings
    app <- includeTid (mkApp tv)
    liftIO $ runSettings settings app
  where
    shutdownHandler io closeSocket = liftIO $ do
      Posix.installHandler Posix.sigTERM (Posix.Catch $ io goodbye >> closeSocket) Nothing
      Posix.installHandler Posix.sigINT (Posix.Catch $ io goodbye >> closeSocket) Nothing

      pure ()

    welcome = logInfoN "PowerDNS-Gerd started."
    goodbye = logInfoN "Graceful shutdown requested, stopping PowerDNS-Gerd..."

    reloadConfig :: TVar Config -> IOL ()
    reloadConfig tv = do
      logInfoN "Reloading config..."
      atomically . writeTVar tv =<< loadConfig (optConfig opts)
