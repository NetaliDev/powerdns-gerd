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

import           Control.Monad (when)
import           Data.Char (isSpace, ord)
import           Data.Foldable (for_)
import           Text.Read (readMaybe)

import           Control.Monad.Logger (Loc, LogLevel, LogSource, LogStr,
                                       LoggingT, askLoggerIO, logDebugN,
                                       logError, logWarnN, runLoggingT,
                                       toLogStr)
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
import           Network.HTTP.Types (Header)
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
import           PowerDNS.Gerd.Utils (quoted)
import           UnliftIO.IORef

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

  uref <- newIORef (error "User not initialized yet" :: User)
  context <- mkContext cfg uref

  let logger' = loggerAddUser uref logger
  pure (genericServeTWithContext (toHandler logger' (Env cenv))
                                 server
                                 context)

loggerAddUser :: IORef User -> Logger -> Logger
loggerAddUser uref logger = \loc src lvl str -> do
    user <- readIORef uref
    logger loc src lvl (str <> toLogStr (pprUser user))
  where
    pprUser u = " user=" <> quoted (getUsername (uName u))

getKey :: Config -> LoggingT IO T.Text
getKey cfg = case cfgUpstreamApiKeyType cfg of
    Key  -> pure buf
    Path -> liftIO $ rstrip <$> T.readFile (T.unpack buf)
  where
    buf = cfgUpstreamApiKey cfg

note :: Monad m => Maybe a -> m a -> m a
note (Just a) _  = pure a
note Nothing err = err

showT :: Show a => a -> T.Text
showT = T.pack . show

prepend :: T.Text -> T.Text -> T.Text
prepend = (<>)

(<+>) :: T.Text -> T.Text -> T.Text
l <+> r = l <> " " <> r

authorizeClientIP :: Request
                  -> [IP.IPRange] -- ^ Allowed client IPs
                  -> [IP.IPRange] -- ^ Trusted proxies
                  -> LoggingT Handler ()
authorizeClientIP req allowedClients trustedProxies = do
    (clientIP, _port)  <- IP.fromSockAddr (remoteHost req)
                            `note` authFailure "Failed to convert client IP"
    logDebugN ("Immediate client has IP address" <+> showT clientIP)
    fs <- getForwardedFor req
    case fs of
        Just (realIP:rest) -> do
            let chain = clientIP : reverse rest
            logDebugN $ "Proxies detected:" <> mconcat (prepend " proxy=" . showT <$> chain)
                                        <+> "realip=" <> showT realIP
            authorizeProxies trustedProxies chain

            if any (ipMatches realIP) allowedClients
                then logDebugN "Client allowed because the first X-Forwarded-For address matches allowFrom"
                else authFailure $ "First X-Forwarded-For address" <+> showT realIP
                                 <+> "does not match any entry from allowedFrom"

        Just [] -> authFailure "X-Forwarded-For is present but empty"
        Nothing ->
            if any (ipMatches clientIP) allowedClients
                then logDebugN "Client allowed because its IP address matches allowFrom"
                else authFailure "Client IP does not match any entry from allowedFrom"

authorizeProxies :: [IP.IPRange] -> [IP.IP] -> LoggingT Handler ()
authorizeProxies trustedProxies = go
  where
    go []     = pure ()
    go (x:xs) | any (ipMatches x) trustedProxies
              = go xs
              | otherwise
              = authFailure ("The proxy " <> T.pack (show x) <> " is not trusted")

ipMatches :: IP.IP -> IP.IPRange -> Bool
ipMatches (IP.IPv4 i) (IP.IPv4Range r) = i `IP.isMatchedTo` r
ipMatches (IP.IPv6 i) (IP.IPv6Range r) = i `IP.isMatchedTo` r
ipMatches _ _                          = False

getForwardedFor :: Request -> LoggingT Handler (Maybe [IP.IP])
getForwardedFor req = do
    hdrs <- traverse selectXFF (requestHeaders req)
    case hdrs of
        [] -> pure Nothing
        _  -> pure (Just (mconcat hdrs))

  where
    selectXFF :: Header -> LoggingT Handler [IP.IP]
    selectXFF ("X-Forwarded-For", x) = traverse parseIP (T.splitOn ", " (decodeLenient x))
    selectXFF _                      = pure []

    parseIP :: T.Text -> LoggingT Handler IP.IP
    parseIP rip = case readMaybe (T.unpack rip) of
        Nothing -> throw400 ("Bad X-Forwarded-For header. Invalid IP address: " <> t2bsl rip)
        Just ip -> pure ip

t2bsl :: T.Text -> BSL.ByteString
t2bsl = BSL.fromStrict . T.encodeUtf8

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: TVar Config -> IORef User -> LoggingT IO (AuthHandler Request User)
authHandler cfg uref = do
    logger <- askLoggerIO
    pure $ mkAuthHandler (\req -> do
                             runLoggingT (handler req) logger
                         )
  where
    handler :: Request -> LoggingT Handler User
    handler req = do
        let xApiKey = lookup "X-API-Key" (requestHeaders req)

        cfg' <- readTVarIO cfg
        apiKey <- xApiKey `note401` "Missing API key"
        case BS.split (fromIntegral (ord ':')) apiKey of
            [name, hash] -> do
              let nam = decodeLenient name
              user <- lookup (Username nam) (cfgUsers cfg')
                      `note` authFailure ("User " <> nam <> " not found")

              logDebugN ("User" <+> quoted (getUsername (uName user)) <+> "found")
              for_ (uAllowedFrom user) $ \allowedIPs -> do
                authorizeClientIP req allowedIPs (cfgTrustedProxies cfg')

              valid <- liftIO (authenticate user hash)
              when (not valid) $ do
                  authFailure ("User " <> nam <> " specified an incorrect password")

              let user' = user { uPerms = loadDefaults (cfgDefaultPerms cfg') (uPerms user) }
              writeIORef uref user'
              pure user'

            _            -> throw400 "Invalid X-API-Key syntax"

    note401 :: Maybe a -> BSL.ByteString -> LoggingT Handler a
    note401 m reason = maybe (throw401 reason) pure m

throw401 :: BSL.ByteString -> LoggingT Handler a
throw401 msg = lift $ throwError (err401 { errBody = msg })

throw400 :: BSL.ByteString -> LoggingT Handler a
throw400 msg = lift $ throwError (err400 { errBody = msg })

decodeLenient :: BS.ByteString -> T.Text
decodeLenient = T.decodeUtf8With lenientDecode

authFailure :: T.Text -> LoggingT Handler a
authFailure why = do
    logWarnN ("Authentication failure:" <+> why)
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

mkContext :: TVar Config -> IORef User -> LoggingT IO (Context CtxtList)
mkContext cfg uref = do
  handler <- authHandler cfg uref
  pure (handler :. EmptyContext)
