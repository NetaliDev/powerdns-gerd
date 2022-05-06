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

import           Control.Monad (unless)
import           Data.Char (isSpace, ord)
import           Data.Foldable (find)
import           Data.Functor ((<&>))
import           Text.Read (readMaybe)

import           Control.Monad.Logger (Loc, LogLevel, LogSource, LogStr,
                                       LoggingT, askLoggerIO, logDebugN,
                                       logError, logWarnN, runLoggingT)
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Except (ExceptT(ExceptT))
import           Control.Monad.Trans.Reader (runReaderT)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.IP as IP
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Text.Encoding.Error (lenientDecode)
import qualified Data.Text.IO as T

import           Network.HTTP.Client (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.Wai (Request(requestHeaders), remoteHost)
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
import           PowerDNS.Gerd.Config (ApiKeyType(..), Config(..))
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

rstrip :: T.Text -> T.Text
rstrip = T.dropWhileEnd isSpace

mkApp :: TVar Config -> LoggingT IO Application
mkApp cfg = do
  logger <- askLoggerIO
  cfg' <- liftIO $ readTVarIO cfg
  url <- liftIO $ parseBaseUrl (T.unpack (cfgUpstreamApiBaseUrl cfg'))
  mgr <- liftIO $ newManager tlsManagerSettings
  key <- getKey cfg'
  let cenv =  PDNS.applyXApiKey key (mkClientEnv mgr url)

  context <- mkContext cfg
  pure (genericServeTWithContext (toHandler logger (Env cenv))
                                 server
                                 context)

getKey :: Config -> LoggingT IO T.Text
getKey cfg = case cfgUpstreamApiKeyType cfg of
    Key  -> pure buf
    Path -> liftIO $ rstrip <$> T.readFile (T.unpack buf)
  where
    buf = cfgUpstreamApiKey cfg

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: TVar Config -> LoggingT IO (AuthHandler Request User)
authHandler cfg = do
    logger <- askLoggerIO
    pure $ mkAuthHandler (\req -> runLoggingT (handler req) logger)
  where
    handler :: Request -> LoggingT Handler User
    handler req = do
        let xApiKey = lookup "X-API-Key" (requestHeaders req)

        cfg' <- readTVarIO cfg
        apiKey <- xApiKey `note401` "Missing API key"
        case BS.split (fromIntegral (ord ':')) apiKey of
            [name, hash] -> do let nam = decodeLenient name
                               user <- case lookup (Username nam) (cfgUsers cfg') of
                                  Nothing -> authFailure ("User " <> nam <> " not found")
                                  Just u -> pure u

                               allowed <- allowedIP req user
                               unless allowed $
                                 authFailure ("User " <> nam <> " denied because its client IP did not match any of their allowFrom entries")

                               valid <- liftIO (authenticate user hash)
                               unless valid $ do
                                 authFailure ("User " <> nam <> " specified an incorrect password")

                               pure (user { uPerms = loadDefaults (cfgDefaultPerms cfg') (uPerms user) })

            _            -> throw400 "Invalid X-API-Key syntax"

    note401 :: Maybe a -> BSL.ByteString -> LoggingT Handler a
    note401 m reason = maybe (throw401 reason) pure m

    throw401 :: BSL.ByteString -> LoggingT Handler a
    throw401 msg = lift $ throwError (err401 { errBody = msg })

    throw400 :: BSL.ByteString -> LoggingT Handler a
    throw400 msg = lift $ throwError (err400 { errBody = msg })

    decodeLenient = T.decodeUtf8With lenientDecode

    parseIP :: T.Text -> Maybe IP.IP
    parseIP = readMaybe . T.unpack

    allowedIP :: Request -> User -> LoggingT Handler Bool
    allowedIP req user | null (uAllowedFrom user) = pure True
                       | Nothing <- maybeClient
                       = False <$ logWarnN "Failed to get client IP address"

                       | Just (clientIP, _port) <- maybeClient
                       = allowedIPClient clientIP req user
      where
        maybeClient = IP.fromSockAddr (remoteHost req)

    allowedIPClient :: IP.IP -> Request -> User -> LoggingT Handler Bool
    allowedIPClient clientIP req user
                       | Just h <- forwardedFor
                       = case traverse parseIP (T.splitOn ", " h) of
                           Nothing -> do logDebugN "Failed to parse one or more IP address in X-Forwarded-For header"
                                         pure False
                           Just clients
                              | any (last clients `matches`) whitelist
                              -> True <$ logDebugN "Client allowed because the final X-Forwarded-For matches allowFrom"
                              | any (clientIP `matches`) whitelist
                              -> True <$ logDebugN "Client allowed because its IP address matches allowFrom"
                              | otherwise
                              -> pure False

                       | otherwise
                       = case find (clientIP `matches`) whitelist of
                           Nothing -> False <$ logDebugN "Client IP not found in any whitelist"
                           Just _ -> True <$ logDebugN "Client allowed because its IP address matches allowFrom"

      where
        matches :: IP.IP -> IP.IPRange -> Bool
        matches (IP.IPv4 i) (IP.IPv4Range r) = i `IP.isMatchedTo` r
        matches (IP.IPv6 i) (IP.IPv6Range r) = i `IP.isMatchedTo` r
        matches _ _                          = False

        whitelist = uAllowedFrom user
        forwardedFor = lookup "X-Forwarded-For" (requestHeaders req) <&> decodeLenient

    authFailure :: T.Text -> LoggingT Handler a
    authFailure why = do
      logWarnN why
      throw401 "Bad authentication"


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

mkContext :: TVar Config -> LoggingT IO (Context CtxtList)
mkContext cfg = do
  handler <- authHandler cfg
  pure (handler :. EmptyContext)
