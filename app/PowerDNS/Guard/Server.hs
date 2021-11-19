{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ScopedTypeVariables #-}
module PowerDNS.Guard.Server
  ( mkApp
  )
where

import           Control.Monad (unless)
import           Data.Char (ord)
import           Data.Coerce (coerce)
import           Data.Foldable (toList, for_)
import           Data.Maybe (isJust)

import           Control.Monad.Logger (logError, runStdoutLoggingT)
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
import           Network.Wai (Request (requestHeaders))
import qualified PowerDNS.API as PDNS
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Guard.Account
import           Servant (Context(..), throwError)
import           Servant.Client (ClientEnv, ClientM, runClientM, ClientError (FailureResponse))
import           Servant.Client (parseBaseUrl)
import           Servant.Client.Streaming (ResponseF(Response), BaseUrl, mkClientEnv)
import           Servant.Server (Application, ServerError(..), err500, err403, Handler(..), err401, err400)
import           Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import           Servant.Server.Generic (genericServeTWithContext, AsServer, genericServerT)
import           UnliftIO (throwIO, MonadUnliftIO, liftIO)
import qualified UnliftIO.Exception as E

import           PowerDNS.Guard.API
import           PowerDNS.Guard.Config (Config(..))
import           PowerDNS.Guard.Types
import           PowerDNS.Guard.Utils
import           PowerDNS.Guard.Permission
import Control.Monad (when)
import qualified Data.Map as M

server :: GuardedAPI AsGuard
server = GuardedAPI
  { servers    = genericServerT . guardedServers
  , zones      = genericServerT . guardedZones
  , cryptokeys = genericServerT . guardedCryptokeys
  , metadata   = genericServerT . guardedMetadata
  , tsigkeys   = genericServerT . guardedTSIGKeys
  }

guardedServers :: Account -> PDNS.ServersAPI AsGuard
guardedServers _ = PDNS.ServersAPI
  { PDNS.apiListServers = const0 forbidden
  , PDNS.apiGetServer   = const1 forbidden
  , PDNS.apiSearch      = const4 forbidden
  , PDNS.apiFlushCache  = const2 forbidden
  , PDNS.apiStatistics  = const3 forbidden
  }

withZonePerms :: Account -> T.Text -> (ZonePerms -> GuardM a) -> GuardM a
withZonePerms acc zone cb = do
    maybe (forbiddenWhy "No permissions exist for this zone")
          cb
          (M.lookup (ZoneId zone) (acZonePerms acc))

matchesRecordSpec :: PDNS.RRSet -> RecordSpec -> Bool
matchesRecordSpec _ AnyRecord = True
matchesRecordSpec PDNS.RRSet{PDNS.rrset_name = rname} (Exact (RelDomain spec)) = rname == spec

matchesRecordTypeSpec :: PDNS.RRSet -> RecordTypeSpec -> Bool
matchesRecordTypeSpec _ AnyRecordType = True
matchesRecordTypeSpec PDNS.RRSet{PDNS.rrset_type = rtype} (Matching types)
  = rtype `elem` types

guardedZones :: Account -> PDNS.ZonesAPI AsGuard
guardedZones acc = PDNS.ZonesAPI
    { PDNS.apiListZones     = const3 forbidden
    , PDNS.apiCreateZone    = const3 forbidden
    , PDNS.apiGetZone       = \server zone includeRRs ->
        withZonePerms acc zone $ \perms ->
          runProxy (PDNS.getZone server zone includeRRs)

    , PDNS.apiDeleteZone    = const2 forbidden
    , PDNS.apiUpdateRecords = \server zone rrs ->
        withZonePerms acc zone $ \perms ->  do
            for_ (PDNS.rrsets rrs) $ \rrset -> do
              let matchingPerms = filter (\(RecordPerm reco recoTy) -> matchesRecordSpec rrset reco && matchesRecordTypeSpec rrset recoTy) (recordPerms perms)
              when (null matchingPerms)
                (forbiddenWhy "No permssions exist for this record or record type")

            runProxy (PDNS.updateRecords server zone rrs)


    , PDNS.apiUpdateZone    = const3 forbidden
    , PDNS.apiTriggerAxfr   = const2 forbidden
    , PDNS.apiNotifySlaves  = const2 forbidden
    , PDNS.apiGetZoneAxfr   = const2 forbidden
    , PDNS.apiRectifyZone   = const2 forbidden
    }

guardedMetadata :: Account -> PDNS.MetadataAPI AsGuard
guardedMetadata _ = PDNS.MetadataAPI
  { PDNS.apiListMetadata   = const2 forbidden
  , PDNS.apiCreateMetadata = const3 forbidden
  , PDNS.apiGetMetadata    = const3 forbidden
  , PDNS.apiUpdateMetadata = const4 forbidden
  , PDNS.apiDeleteMetadata = const3 forbidden
  }

guardedTSIGKeys :: Account -> PDNS.TSIGKeysAPI AsGuard
guardedTSIGKeys _ = PDNS.TSIGKeysAPI
  { PDNS.apiListTSIGKeys  = const1 forbidden
  , PDNS.apiCreateTSIGKey = const2 forbidden
  , PDNS.apiGetTSIGKey    = const2 forbidden
  , PDNS.apiUpdateTSIGKey = const3 forbidden
  , PDNS.apiDeleteTSIGKey = const2 forbidden
  }

guardedCryptokeys :: Account -> PDNS.CryptokeysAPI AsGuard
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

    responseFToServerErr :: ResponseF BSL.ByteString -> ServerError
    responseFToServerErr (Response (Status code message) headers _version body)
      = ServerError code (BS8.unpack message) body (toList headers)


forbidden :: GuardM a
forbidden = throwIO err403

forbiddenWhy :: BSL.ByteString -> GuardM a
forbiddenWhy reason = throwIO err403{ errBody = reason }

-- | A natural transformation turning a GuardM into a plain Servant handler.
-- See https://docs.servant.dev/en/stable/cookbook/using-custom-monad/UsingCustomMonad.html
-- One of the core themes is that we want an unliftable monad. Inside GuardM we throw
-- ServerError as an exception, and this handler catches them back. We also
-- catch outstanding exceptions and produce a 500 error here instead. This allows
-- middlewares to log these requests and responses as well.
toHandler :: Env -> GuardM a -> Handler a
toHandler env = Handler . ExceptT . flip runReaderT env . runStdoutLoggingT . runGuardM . catchRemEx
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

mkApp :: Config -> IO Application
mkApp cfg = do
  url <- parseBaseUrl (T.unpack (cfgUpstreamApiBaseUrl cfg))
  mgr <- newManager tlsManagerSettings
  let clientEnv =  PDNS.applyXApiKey (cfgUpstreamApiKey cfg) (mkClientEnv mgr url)
  let env = Env clientEnv
  pure (genericServeTWithContext (toHandler env) server (ourContext cfg))

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: Config -> AuthHandler Request Account
authHandler cfg = mkAuthHandler handler
  where
    db :: [Account]
    db = cfgAccounts cfg

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
            [user, hash] -> do mAccount <- liftIO $ authenticate db (decodeLenient user) hash
                               mAccount `note401` "Bad authentication"
            _            -> throw400 "Invalid X-API-Key syntax"


ourContext :: Config -> Context (AuthHandler Request Account ': '[])
ourContext cfg = authHandler cfg :. EmptyContext
