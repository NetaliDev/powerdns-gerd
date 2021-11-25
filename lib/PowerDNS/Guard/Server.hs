{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeOperators       #-}
module PowerDNS.Guard.Server
  ( mkApp
  )
where

import           Control.Monad (when)
import           Data.Char (ord)
import           Data.Foldable (for_, toList)

import           Control.Monad.Logger (LoggingT, filterLogger, logDebugN,
                                       logError, logErrorN, runStdoutLoggingT)
import           Control.Monad.Reader (ask)
import           Control.Monad.Trans.Except (ExceptT(ExceptT))
import           Control.Monad.Trans.Reader (runReaderT)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Text.Encoding.Error (lenientDecode)
import           Network.HTTP.Client (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.HTTP.Types (Status(Status))
import           Network.Wai (Request(requestHeaders))
import qualified PowerDNS.API as PDNS
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Guard.User
import           Servant (Context(..), throwError)
import           Servant.Client (ClientError(FailureResponse), ClientM,
                                 parseBaseUrl, runClientM)
import           Servant.Client.Streaming (ResponseF(Response), mkClientEnv)
import           Servant.Server (Application, Handler(..), ServerError(..),
                                 err400, err401, err403, err500)
import           Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import           Servant.Server.Generic (genericServeTWithContext,
                                         genericServerT)
import           UnliftIO (MonadIO, liftIO, throwIO)
import qualified UnliftIO.Exception as E

import           Control.Monad (filterM)
import           PowerDNS.Guard.API
import           PowerDNS.Guard.Config (Config(..))
import           PowerDNS.Guard.Permission
import           PowerDNS.Guard.Types
import           PowerDNS.Guard.Utils

server :: GuardedAPI AsGuard
server = GuardedAPI
  { versions   = genericServerT . guardedVersions
  , servers    = genericServerT . guardedServers
  , zones      = genericServerT . guardedZones
  , cryptokeys = genericServerT . guardedCryptokeys
  , metadata   = genericServerT . guardedMetadata
  , tsigkeys   = genericServerT . guardedTSIGKeys
  }

guardedVersions :: User -> PDNS.VersionsAPI AsGuard
guardedVersions _ = PDNS.VersionsAPI
  { PDNS.apiListVersions = runProxy PDNS.listVersions
  }

guardedServers :: User -> PDNS.ServersAPI AsGuard
guardedServers _ = PDNS.ServersAPI
  { PDNS.apiListServers = const0 forbidden
  , PDNS.apiGetServer   = const1 forbidden
  , PDNS.apiSearch      = const4 forbidden
  , PDNS.apiFlushCache  = const2 forbidden
  , PDNS.apiStatistics  = const3 forbidden
  }

notNull :: Foldable t => t a -> Bool
notNull = not . null

-- | Filters a list of RRSet to only those we have any permissions on
filterRRSets :: ZoneId -> [ElabDomainPerm] -> [PDNS.RRSet] -> GuardM [PDNS.RRSet]
filterRRSets zone eperms = filterM (\rrset -> notNull <$> filterDomainPermsRRSet zone rrset eperms)

filterDomainPermsRRSet :: ZoneId -> PDNS.RRSet -> [ElabDomainPerm] -> GuardM [ElabDomainPerm]
filterDomainPermsRRSet zone rrset eperms = do
  let nam = PDNS.rrset_name rrset
  labels <- notePanic (hush (parseAbsDomainLabels nam))
                      ("failed to parse rrset: " <> nam)

  pure $ filterDomainPerms zone labels (PDNS.rrset_type rrset) eperms

-- | Ensure the user has sufficient permissions for this RRset
ensureHasRecordPermissions :: [ElabDomainPerm] -> ZoneId -> PDNS.RRSet -> GuardM ()
ensureHasRecordPermissions eperms zone rrset = do
    matching <- filterDomainPermsRRSet zone rrset eperms
    when (null matching) forbidden
    logDebugN ("Matching permissions:\n" <> T.unlines (showT <$> matching))

showT :: Show a => a -> T.Text
showT = T.pack . show

filterZone :: [ElabDomainPerm] -> PDNS.Zone -> GuardM PDNS.Zone
filterZone eperms zone = do
    name <- notePanic (PDNS.zone_name zone) ("Missing zone name: " <> showT zone)

    filtered <- maybe (pure Nothing)
                      (fmap Just . filterRRSets (ZoneId name) eperms)
                      (PDNS.zone_rrsets zone)
    pure $ zone { PDNS.zone_rrsets = filtered }

guardedZones :: User -> PDNS.ZonesAPI AsGuard
guardedZones acc = PDNS.ZonesAPI
    { PDNS.apiListZones     = const3 forbidden
    , PDNS.apiCreateZone    = const3 forbidden
    , PDNS.apiGetZone       = \srv zone rrs -> do
        case zoneViewPerm acc (ZoneId zone) of
          Nothing -> forbidden
          Just Filtered -> filterZone eperms =<< runProxy (PDNS.getZone srv zone rrs)
          Just Unfiltered -> runProxy (PDNS.getZone srv zone rrs)

    , PDNS.apiDeleteZone    = const2 forbidden
    , PDNS.apiUpdateRecords = \srv zone rrs -> do
        when (null $ PDNS.rrsets rrs) forbidden
        for_ (PDNS.rrsets rrs) $ \rrset -> do
            ensureHasRecordPermissions eperms (ZoneId zone) rrset
        runProxy (PDNS.updateRecords srv zone rrs)


    , PDNS.apiUpdateZone    = const3 forbidden
    , PDNS.apiTriggerAxfr   = const2 forbidden
    , PDNS.apiNotifySlaves  = const2 forbidden
    , PDNS.apiGetZoneAxfr   = const2 forbidden
    , PDNS.apiRectifyZone   = const2 forbidden
    }
  where
    eperms :: [ElabDomainPerm]
    eperms = elaborateDomainPerms acc

guardedMetadata :: User -> PDNS.MetadataAPI AsGuard
guardedMetadata _ = PDNS.MetadataAPI
  { PDNS.apiListMetadata   = const2 forbidden
  , PDNS.apiCreateMetadata = const3 forbidden
  , PDNS.apiGetMetadata    = const3 forbidden
  , PDNS.apiUpdateMetadata = const4 forbidden
  , PDNS.apiDeleteMetadata = const3 forbidden
  }

guardedTSIGKeys :: User -> PDNS.TSIGKeysAPI AsGuard
guardedTSIGKeys _ = PDNS.TSIGKeysAPI
  { PDNS.apiListTSIGKeys  = const1 forbidden
  , PDNS.apiCreateTSIGKey = const2 forbidden
  , PDNS.apiGetTSIGKey    = const2 forbidden
  , PDNS.apiUpdateTSIGKey = const3 forbidden
  , PDNS.apiDeleteTSIGKey = const2 forbidden
  }

guardedCryptokeys :: User -> PDNS.CryptokeysAPI AsGuard
guardedCryptokeys _ = PDNS.CryptokeysAPI
    { PDNS.apiListCryptokeys  = const2 forbidden
    , PDNS.apiCreateCryptokey = const3 forbidden
    , PDNS.apiGetCryptokey    = const3 forbidden
    , PDNS.apiUpdateCryptokey = const4 forbidden
    , PDNS.apiDeleteCryptokey = const3 forbidden
    }

-- | Runs a ClientM action and throws client errors back as server errors.
runProxy :: ClientM a -> GuardM a
runProxy act = do
    ce <- envProxyEnv <$> ask
    r <- liftIO $ runClientM act ce
    either handleErr pure r
  where
    handleErr (FailureResponse _ resp) = throwIO (responseFToServerErr resp)
    handleErr other                    = throwIO other

    responseFToServerErr :: ResponseF BSL.ByteString -> ServerError
    responseFToServerErr (Response (Status code message) headers _version body)
      = ServerError code (BS8.unpack message) body (toList headers)

forbidden :: GuardM a
forbidden = throwIO err403

runLog :: MonadIO m => Int -> LoggingT m a -> m a
runLog verbosity = runStdoutLoggingT . filterLogger (logFilter verbosity)

-- | A natural transformation turning a GuardM into a plain Servant handler.
-- See https://docs.servant.dev/en/stable/cookbook/using-custom-monad/UsingCustomMonad.html
-- One of the core themes is that we want an unliftable monad. Inside GuardM we throw
-- ServerError as an exception, and this handler catches them back. We also
-- catch outstanding exceptions and produce a 500 error here instead. This allows
-- middlewares to log these requests and responses as well.
toHandler :: Env -> GuardM a -> Handler a
toHandler env = Handler . ExceptT . flip runReaderT env . runLog (envVerbosity env) . runGuardM . catchRemEx
  where
    catchRemEx :: forall a. GuardM a -> GuardM (Either ServerError a)
    catchRemEx handler = (Right <$> handler) `E.catches` exceptions

    exceptions :: [E.Handler GuardM (Either ServerError a)]
    exceptions = [ E.Handler prpgSrvErr
                , E.Handler handleAnyException
                ]

    handleAnyException :: E.SomeException -> GuardM (Either ServerError a)
    handleAnyException ex = do
        logException ex
        pure (Left (err500 {errBody = "Internal error"}))

    logException :: E.SomeException -> GuardM ()
    logException ex = do
        $logError "Unhandled exception"
        $logError (T.pack (E.displayException ex))

    -- Propagate any thrown ServerError as Left for Servant.
    prpgSrvErr :: ServerError -> GuardM (Either ServerError a)
    prpgSrvErr = pure . Left

mkApp :: Int -> Config -> IO Application
mkApp verbosity cfg = do
  url <- parseBaseUrl (T.unpack (cfgUpstreamApiBaseUrl cfg))
  mgr <- newManager tlsManagerSettings
  let clientEnv =  PDNS.applyXApiKey (cfgUpstreamApiKey cfg) (mkClientEnv mgr url)
  let env = Env clientEnv verbosity

  pure (genericServeTWithContext (toHandler env) server (ourContext cfg))

hush :: Either a b -> Maybe b
hush = either (const Nothing) Just

notePanic :: Maybe a -> T.Text -> GuardM a
notePanic m t = maybe (logErrorN t >> throwIO err500) pure m

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: Config -> AuthHandler Request User
authHandler cfg = mkAuthHandler handler
  where
    db :: [User]
    db = cfgUsers cfg

    note401 :: Maybe a -> BSL.ByteString -> Handler a
    note401 m reason = maybe (throw401 reason) pure m

    throw401 :: BSL.ByteString -> Handler a
    throw401 msg = throwError (err401 { errBody = msg })

    throw400 :: BSL.ByteString -> Handler a
    throw400 msg = throwError (err400 { errBody = msg })

    decodeLenient = T.decodeUtf8With lenientDecode

    handler req = do
        apiKey <- lookup "X-API-Key" (requestHeaders req) `note401` "Missing API key"
        case BS.split (fromIntegral (ord ':')) apiKey of
            [user, hash] -> do mUser <- liftIO $ authenticate db (decodeLenient user) hash
                               mUser `note401` "Bad authentication"
            _            -> throw400 "Invalid X-API-Key syntax"


type CtxtList = AuthHandler Request User ': '[]
ourContext :: Config -> Context CtxtList
ourContext cfg = authHandler cfg :. EmptyContext
