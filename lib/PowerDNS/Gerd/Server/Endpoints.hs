{-# LANGUAGE OverloadedStrings #-}

module PowerDNS.Gerd.Server.Endpoints
  ( server
  )
where

import           PowerDNS.Gerd.API
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Types
import           PowerDNS.Gerd.User (User)

import           Control.Monad (filterM, when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (logDebugN, logErrorN, logWarnN)
import           Control.Monad.Reader (ask)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import           Data.Foldable (for_, toList)
import qualified Data.Text as T
import           Network.HTTP.Types (Status(Status))
import qualified PowerDNS.API as PDNS
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Gerd.Permission
import           PowerDNS.Gerd.Utils
import           Servant (ServerError, err403, err500)
import           Servant.Client (ClientError(FailureResponse), ClientM,
                                 ResponseF(..), runClientM)
import           Servant.Server (ServerError(ServerError))
import           Servant.Server.Generic (genericServerT)
import           UnliftIO (throwIO)

server :: GuardedAPI AsGerd
server = GuardedAPI
  { versions   = genericServerT . guardedVersions
  , servers    = genericServerT . guardedServers
  , zones      = genericServerT . guardedZones
  , cryptokeys = genericServerT . guardedCryptokeys
  , metadata   = genericServerT . guardedMetadata
  , tsigkeys   = genericServerT . guardedTSIGKeys
  }

guardedVersions :: User -> PDNS.VersionsAPI AsGerd
guardedVersions _ = PDNS.VersionsAPI
  { PDNS.apiListVersions = runProxy PDNS.listVersions
  }

guardedServers :: User -> PDNS.ServersAPI AsGerd
guardedServers _ = PDNS.ServersAPI
  { PDNS.apiListServers = const0 forbidden
  , PDNS.apiGetServer   = const1 forbidden
  , PDNS.apiSearch      = const4 forbidden
  , PDNS.apiFlushCache  = const2 forbidden
  , PDNS.apiStatistics  = const3 forbidden
  }

guardedZones :: User -> PDNS.ZonesAPI AsGerd
guardedZones acc = PDNS.ZonesAPI
    { PDNS.apiListZones     = const3 forbidden
    , PDNS.apiCreateZone    = const3 forbidden
    , PDNS.apiGetZone       = \srv zone rrs -> do
        case zoneViewPerm acc (ZoneId zone) of
          Nothing -> forbidden
          Just Filtered -> filterZone eperms =<< runProxy (PDNS.getZone srv zone rrs)
          Just Unfiltered -> runProxy (PDNS.getZone srv zone rrs)

    , PDNS.apiDeleteZone    = \srv zone -> do
        authorize "delete zone" (getZonePermission zpDeleteZone zone acc)
        runProxy (PDNS.deleteZone srv zone)

    , PDNS.apiUpdateRecords = \srv zone rrs -> do
        when (null $ PDNS.rrsets rrs) forbidden
        for_ (PDNS.rrsets rrs) $ \rrset -> do
            ensureHasRecordPermissions eperms (ZoneId zone) rrset
        runProxy (PDNS.updateRecords srv zone rrs)

    , PDNS.apiUpdateZone    = \srv zone zoneData -> do
        authorize "update zone" (getZonePermission zpUpdateZone zone acc)
        runProxy (PDNS.updateZone srv zone zoneData)

    , PDNS.apiTriggerAxfr   = \srv zone -> do
        authorize "trigger axfr" (getZonePermission zpTriggerAxfr zone acc)
        runProxy (PDNS.triggerAxfr srv zone)

    , PDNS.apiNotifySlaves  = \srv zone -> do
        authorize "notify slaves" (getZonePermission zpNotifySlaves zone acc)
        runProxy (PDNS.notifySlaves srv zone)

    , PDNS.apiGetZoneAxfr   = \srv zone -> do
        authorize "get zone axfr" (getZonePermission zpGetZoneAxfr zone acc)
        runProxy (PDNS.getZoneAxfr srv zone)

    , PDNS.apiRectifyZone   = \srv zone -> do
        authorize "rectify zone" (getZonePermission zpRectifyZone zone acc)
        runProxy (PDNS.rectifyZone srv zone)
    }
  where
    eperms :: [ElabDomainPerm]
    eperms = elaborateDomainPerms acc

guardedMetadata :: User -> PDNS.MetadataAPI AsGerd
guardedMetadata _ = PDNS.MetadataAPI
  { PDNS.apiListMetadata   = const2 forbidden
  , PDNS.apiCreateMetadata = const3 forbidden
  , PDNS.apiGetMetadata    = const3 forbidden
  , PDNS.apiUpdateMetadata = const4 forbidden
  , PDNS.apiDeleteMetadata = const3 forbidden
  }

guardedTSIGKeys :: User -> PDNS.TSIGKeysAPI AsGerd
guardedTSIGKeys _ = PDNS.TSIGKeysAPI
  { PDNS.apiListTSIGKeys  = const1 forbidden
  , PDNS.apiCreateTSIGKey = const2 forbidden
  , PDNS.apiGetTSIGKey    = const2 forbidden
  , PDNS.apiUpdateTSIGKey = const3 forbidden
  , PDNS.apiDeleteTSIGKey = const2 forbidden
  }

guardedCryptokeys :: User -> PDNS.CryptokeysAPI AsGerd
guardedCryptokeys _ = PDNS.CryptokeysAPI
    { PDNS.apiListCryptokeys  = const2 forbidden
    , PDNS.apiCreateCryptokey = const3 forbidden
    , PDNS.apiGetCryptokey    = const3 forbidden
    , PDNS.apiUpdateCryptokey = const4 forbidden
    , PDNS.apiDeleteCryptokey = const3 forbidden
    }

-- | Runs a ClientM action and throws client errors back as server errors.
runProxy :: ClientM a -> GerdM a
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

authorize :: T.Text -> Authorization -> GerdM ()
authorize title Forbidden  = do
  logWarnN (title <> " denied, insufficient permissions")
  forbidden
authorize _     Authorized = pure ()


-- | Filters a list of RRSet to only those we have any permissions on
filterRRSets :: ZoneId -> [ElabDomainPerm] -> [PDNS.RRSet] -> GerdM [PDNS.RRSet]
filterRRSets zone eperms = filterM (\rrset -> not . null <$> filterDomainPermsRRSet zone rrset eperms)

filterDomainPermsRRSet :: ZoneId -> PDNS.RRSet -> [ElabDomainPerm] -> GerdM [ElabDomainPerm]
filterDomainPermsRRSet zone rrset eperms = do
  let nam = PDNS.rrset_name rrset
  labels <- notePanic (hush (parseAbsDomainLabels nam))
                      ("failed to parse rrset: " <> nam)

  logDebugN ("Find matching permissions for: " <> PDNS.rrset_name rrset)

  pure $ filterDomainPerms zone labels (PDNS.rrset_type rrset) eperms

-- | Ensure the user has sufficient permissions for this RRset
ensureHasRecordPermissions :: [ElabDomainPerm] -> ZoneId -> PDNS.RRSet -> GerdM ()
ensureHasRecordPermissions eperms zone rrset = do
    matching <- filterDomainPermsRRSet zone rrset eperms
    when (null matching) forbidden
    logDebugN ("Matching permissions:\n" <> T.unlines (pprElabDomainPerm <$> matching))

showT :: Show a => a -> T.Text
showT = T.pack . show

filterZone :: [ElabDomainPerm] -> PDNS.Zone -> GerdM PDNS.Zone
filterZone eperms zone = do
    name <- notePanic (PDNS.zone_name zone) ("Missing zone name: " <> showT zone)

    filtered <- maybe (pure Nothing)
                      (fmap Just . filterRRSets (ZoneId name) eperms)
                      (PDNS.zone_rrsets zone)
    pure $ zone { PDNS.zone_rrsets = filtered }

forbidden :: GerdM a
forbidden = throwIO err403

notePanic :: Maybe a -> T.Text -> GerdM a
notePanic m t = maybe (logErrorN t >> throwIO err500) pure m
