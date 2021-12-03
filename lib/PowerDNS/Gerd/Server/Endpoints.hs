{-# LANGUAGE OverloadedStrings #-}

module PowerDNS.Gerd.Server.Endpoints
  ( server
  )
where

import           PowerDNS.Gerd.API
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Types
import           PowerDNS.Gerd.User (User(..))

import           Control.Monad (filterM, when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (logDebugN, logErrorN, logWarnN)
import           Control.Monad.Reader (ask)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import           Data.Foldable (for_, toList)
import qualified Data.Map as M
import           Data.Maybe (catMaybes)
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

wither :: Applicative f => (a -> f (Maybe b)) -> [a] -> f [b]
wither f t = catMaybes <$> traverse f t

-- | Given a 'PermSet' selector, raise a forbidden error if the authorization is set to forbid, otherwise call
-- the provided continuation with the authorization token.
withPerm :: T.Text -> (PermSet M.Map -> Authorization a) -> User -> (a -> GerdM b) -> GerdM b
withPerm title f user act = case f (_uPerms user) of
  Forbidden      -> deny title
  Authorized tok -> do
    logDebugN ("Authorize: " <> title)
    act tok

-- | Given a 'ZonePermission' selector, raise a forbidden error if the authorization is set to forbid, otherwise call
-- the provided continuation with the authorization token.
withZonePerm :: T.Text -> (ZonePermissions -> Authorization a) -> T.Text -> User -> (a -> GerdM b) -> GerdM b
withZonePerm title f zone user act = case getZonePermission f zone user of
  Forbidden      -> deny title
  Authorized tok -> act tok

-- | Variant of 'withZonePerm' that throws away the authorization token.
authorizeZone :: T.Text -> (ZonePermissions -> Authorization ()) -> T.Text -> User -> GerdM ()
authorizeZone title f zone user = withZonePerm title f zone user (\_tok -> pure ())

-- | Variant of 'withPerm' that throws away the authorization token.
authorize :: T.Text -> (PermSet M.Map -> Authorization ()) -> User -> GerdM ()
authorize title f user = withPerm title f user (\_tok -> pure ())

guardedZones :: User -> PDNS.ZonesAPI AsGerd
guardedZones acc = PDNS.ZonesAPI
    { PDNS.apiListZones     = \srv zone dnssec -> do
        withPerm "zone list" psListZones acc $ \perm -> do
          zs <- runProxy (PDNS.listZones srv zone dnssec)
          case perm of
            Filtered   -> wither (filterZoneMaybe eperms) zs
            Unfiltered -> pure zs

    , PDNS.apiCreateZone    = \srv rrset zone -> do
        authorize "zone create" psCreateZone acc
        runProxy (PDNS.createZone srv rrset zone)

    , PDNS.apiGetZone       = \srv zone rrs -> do
        withZonePerm "view zone" zpViewZone zone acc $ \perm -> do
          z <- runProxy (PDNS.getZone srv zone rrs)
          case perm of
            Filtered   -> filterZone eperms z
            Unfiltered -> pure z

    , PDNS.apiDeleteZone    = \srv zone -> do
        authorizeZone "zone delete" zpDeleteZone zone acc
        runProxy (PDNS.deleteZone srv zone)

    , PDNS.apiUpdateRecords = \srv zone rrs -> do
        -- Ensure we do not forward requests without RRSets to the upstream API.
        when (null (PDNS.rrsets rrs)) $
          deny "zone records update without rrsets"

        for_ (PDNS.rrsets rrs) $ \rrset -> do
            ensureHasRecordPermissions eperms (ZoneId zone) rrset

        runProxy (PDNS.updateRecords srv zone rrs)

    , PDNS.apiUpdateZone    = \srv zone zoneData -> do
        authorizeZone "zone update" zpUpdateZone zone acc
        runProxy (PDNS.updateZone srv zone zoneData)

    , PDNS.apiTriggerAxfr   = \srv zone -> do
        authorizeZone "axfr trigger" zpTriggerAxfr zone acc
        runProxy (PDNS.triggerAxfr srv zone)

    , PDNS.apiNotifySlaves  = \srv zone -> do
        authorizeZone "slave notification" zpNotifySlaves zone acc
        runProxy (PDNS.notifySlaves srv zone)

    , PDNS.apiGetZoneAxfr   = \srv zone -> do
        authorizeZone "axfr view" zpGetZoneAxfr zone acc
        runProxy (PDNS.getZoneAxfr srv zone)

    , PDNS.apiRectifyZone   = \srv zone -> do
        authorizeZone "zone rectify" zpRectifyZone zone acc
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
-- This is used to forward requests to the upstream API.
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

deny :: T.Text -> GerdM a
deny title = do
  logWarnN ("Deny: " <> title)
  forbidden

-- | Filters a list of RRSet to only those we have any permissions on
filterRRSets :: ZoneId -> [ElabDomainPerm] -> [PDNS.RRSet] -> GerdM [PDNS.RRSet]
filterRRSets zone eperms = filterM (\rrset -> not . null <$> filterDomainPermsRRSet zone rrset eperms)

-- | Find all elaborated domain permissions that match a given RRSet in a zone.
filterDomainPermsRRSet :: ZoneId -> PDNS.RRSet -> [ElabDomainPerm] -> GerdM [ElabDomainPerm]
filterDomainPermsRRSet zone rrset eperms = do
  let nam = PDNS.rrset_name rrset
  labels <- notePanic (hush (parseAbsDomainLabels nam))
                      ("failed to parse rrset: " <> nam)

  logDebugN ("Find matching permissions for: " <> PDNS.rrset_name rrset)

  pure $ filterDomainPerms zone labels (PDNS.rrset_type rrset) eperms

-- | Ensure the user has sufficient permissions for this RRset
ensureHasRecordPermissions :: [ElabDomainPerm] -> ZoneId -> PDNS.RRSet -> GerdM ()
ensureHasRecordPermissions eperms zone@(ZoneId raw) rrset = do
    matching <- filterDomainPermsRRSet zone rrset eperms
    when (null matching)
      (deny ("update records for zone " <> raw))
    logDebugN ("Matching permissions:\n" <> T.unlines (pprElabDomainPerm <$> matching))

showT :: Show a => a -> T.Text
showT = T.pack . show

-- | Version of 'filterZone' that produces Nothing if no RRSets are left.
filterZoneMaybe :: [ElabDomainPerm] -> PDNS.Zone -> GerdM (Maybe PDNS.Zone)
filterZoneMaybe eperms zone = do
  z <- filterZone eperms zone
  if (null (PDNS.zone_rrsets z))
    then pure Nothing
    else pure (Just z)

-- | Given some elaborated domain permissions, filter out all RRSets for which we do not have matching domain permissions for.
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
