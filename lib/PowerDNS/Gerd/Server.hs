-- |
-- Module: PowerDNS.Gerd.Server
-- Description: Defines the WAI interface for the powerdns-gerd server
--
-- This module defines a WAI 'Application' builder which also handles
-- user authentication via libsodium.,
--
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeOperators       #-}
module PowerDNS.Gerd.Server
  ( mkApp
  )
where

import           Data.Char (ord)

import           Control.Monad.Logger (Loc, LogLevel, LogSource, LogStr,
                                       LoggingT, askLoggerIO, logError,
                                       runLoggingT)
import           Control.Monad.Trans.Except (ExceptT(ExceptT))
import           Control.Monad.Trans.Reader (runReaderT)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Text.Encoding.Error (lenientDecode)
import           Network.HTTP.Client (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.Wai (Request(requestHeaders))
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Gerd.User
import           Servant (Context(..), throwError)
import           Servant.Client (parseBaseUrl)
import           Servant.Client.Streaming (mkClientEnv)
import           Servant.Server (Application, Handler(..), ServerError(..),
                                 err400, err401, err500)
import           Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import           Servant.Server.Generic (genericServeTWithContext)
import           UnliftIO (TVar, liftIO, readTVarIO)
import qualified UnliftIO.Exception as E

import           Control.Applicative ((<|>))
import           PowerDNS.Gerd.Config (Config(..))
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Server.Endpoints
import           PowerDNS.Gerd.Types

type Logger = Loc -> LogSource -> LogLevel -> LogStr -> IO ()

-- | A natural transformation turning a GerdM into a plain Servant handler.
-- See https://docs.servant.dev/en/stable/cookbook/using-custom-monad/UsingCustomMonad.html
-- One of the core themes is that we want an unliftable monad. Inside GerdM we throw
-- ServerError as an exception, and this handler catches them back. We also
-- catch outstanding exceptions and produce a 500 error here instead. This allows
-- middlewares to log these requests and responses as well.
toHandler :: Logger -> Env -> GerdM a -> Handler a
toHandler logger env = Handler . ExceptT . flip runReaderT env . flip runLoggingT logger . runGerdM . catchRemEx
  where
    catchRemEx :: forall a. GerdM a -> GerdM (Either ServerError a)
    catchRemEx handler = (Right <$> handler) `E.catches` exceptions

    exceptions :: [E.Handler GerdM (Either ServerError a)]
    exceptions = [ E.Handler prpgSrvErr
                , E.Handler handleAnyException
                ]

    handleAnyException :: E.SomeException -> GerdM (Either ServerError a)
    handleAnyException ex = do
        logException ex
        pure (Left (err500 {errBody = "Internal error"}))

    logException :: E.SomeException -> GerdM ()
    logException ex = do
        $logError "Unhandled exception"
        $logError (T.pack (E.displayException ex))

    -- Propagate any thrown ServerError as Left for Servant.
    prpgSrvErr :: ServerError -> GerdM (Either ServerError a)
    prpgSrvErr = pure . Left

mkApp :: TVar Config -> LoggingT IO Application
mkApp cfg = do
  logger <- askLoggerIO
  cfg' <- liftIO $ readTVarIO cfg
  url <- liftIO $ parseBaseUrl (T.unpack (cfgUpstreamApiBaseUrl cfg'))
  mgr <- liftIO $ newManager tlsManagerSettings
  let cenv =  PDNS.applyXApiKey (cfgUpstreamApiKey cfg') (mkClientEnv mgr url)

  pure (genericServeTWithContext (toHandler logger (Env cenv))
                                 server
                                 (ourContext cfg))

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: TVar Config -> AuthHandler Request User
authHandler cfg = mkAuthHandler handler
  where
    note401 :: Maybe a -> BSL.ByteString -> Handler a
    note401 m reason = maybe (throw401 reason) pure m

    throw401 :: BSL.ByteString -> Handler a
    throw401 msg = throwError (err401 { errBody = msg })

    throw400 :: BSL.ByteString -> Handler a
    throw400 msg = throwError (err400 { errBody = msg })

    decodeLenient = T.decodeUtf8With lenientDecode

    handler req = do
        cfg' <- readTVarIO cfg
        apiKey <- lookup "X-API-Key" (requestHeaders req) `note401` "Missing API key"
        case BS.split (fromIntegral (ord ':')) apiKey of
            [name, hash] -> do mUser <- liftIO $ authenticate (cfgUsers cfg') (decodeLenient name) hash
                               user <- mUser `note401` "Bad authentication"
                               pure (user { uPerms = loadDefaults (cfgDefaultPerms cfg') (uPerms user) })

            _            -> throw400 "Invalid X-API-Key syntax"

loadDefaults :: Perms -> Perms -> Perms
loadDefaults def x =
  Perms { permApiVersions       = go permApiVersions
        , permServerList        = go permServerList
        , permServerView        = go permServerView
        , permSearch            = go permSearch
        , permFlushCache        = go permFlushCache
        , permStatistics        = go permStatistics
        , permZoneCreate        = go permZoneCreate
        , permZoneList          = go permZoneList
        , permZoneView          = go permZoneView
        , permZoneUpdate        = go permZoneUpdate
        , permZoneUpdateRecords = go permZoneUpdateRecords
        , permZoneDelete        = go permZoneDelete
        , permZoneTriggerAxfr   = go permZoneTriggerAxfr
        , permZoneGetAxfr       = go permZoneGetAxfr
        , permZoneNotifySlaves  = go permZoneNotifySlaves
        , permZoneRectify       = go permZoneRectify
        , permZoneMetadata      = go permZoneMetadata
        , permZoneCryptokeys    = go permZoneCryptokeys
        , permTSIGKeyList       = go permTSIGKeyList
        , permTSIGKeyCreate     = go permTSIGKeyCreate
        , permTSIGKeyView       = go permTSIGKeyView
        , permTSIGKeyUpdate     = go permTSIGKeyUpdate
        , permTSIGKeyDelete     = go permTSIGKeyDelete
        }
  where
    go :: (Perms -> WithDoc (Maybe t) s) -> WithDoc (Maybe t) s
    go s = WithDoc (withoutDoc (s x) <|> withoutDoc (s def))

type CtxtList = AuthHandler Request User ': '[]
ourContext :: TVar Config -> Context CtxtList
ourContext cfg = authHandler cfg :. EmptyContext
