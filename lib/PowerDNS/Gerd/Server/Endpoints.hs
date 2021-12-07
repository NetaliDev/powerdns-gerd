{-# LANGUAGE OverloadedLabels  #-}
{-# LANGUAGE OverloadedStrings #-}

module PowerDNS.Gerd.Server.Endpoints
  ( server
  )
where

import           PowerDNS.Gerd.API
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Types
import           PowerDNS.Gerd.User (User(..))

import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (logDebugN, logErrorN, logWarnN)
import           Control.Monad.Reader (ask)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import           Data.Foldable (for_, toList, traverse_)
import           Data.Maybe (catMaybes, fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TL

import           Network.HTTP.Types (Status(Status))
import qualified PowerDNS.API as PDNS
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Gerd.Permission
import           PowerDNS.Gerd.Utils
import           Servant (ServerError, err403, err422, err500, errBody)
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


-- | Ensure the user has sufficient permissions for this record update
authorizeRecordUpdate :: [DomTyPat] -> PDNS.RRSet -> GerdM ()
authorizeRecordUpdate pats rrset = do
    let ty = PDNS.rrset_type rrset
    dom <- parseDom (PDNS.rrset_name rrset)

    let matching = filter (matchesDomTyPat dom ty) pats
    when (null matching) $ do
      logWarnN ("No matching permissions for: " <> domain)
      forbidden

    logDebugN ("Allowed update on " <> domain <> " by:")
    traverse_ (logDebugN . showT) matching
  where
    domain = "<" <> PDNS.rrset_name rrset <> ">"

parseZone :: T.Text -> GerdM ZoneId
parseZone t = either (\err -> unprocessableWhy ("Cannot parse zone: " <> T.pack err))
                      (pure . ZoneId)
                      (parseAbsDomainLabels t)

parseDom :: T.Text -> GerdM DomainLabels
parseDom t = either (\err -> unprocessableWhy ("Cannot parse domain: " <> T.pack err))
                    pure
                    (parseAbsDomainLabels t)

handleAuthRes1 :: (Show pat, Show tok) => [Authorization tok pat] -> GerdM tok
handleAuthRes1 [] = do
  logDebugN "No matching permissions"
  forbidden
handleAuthRes1 [x@(Authorization _ _ tok)] = do
  logDebugN ("Allowed by: " <> showT x)
  pure tok
handleAuthRes1 xs = do
  logWarnN "Multiple matching permissions found"
  traverse_ (logWarnN . showT) xs
  throwIO err500{ errBody = "Multiple matching permissions found" }

handleAuthResSome :: (Show pat, Show tok) => [Authorization tok pat] -> GerdM [tok]
handleAuthResSome [] = do
  logDebugN "No matching permissions"
  forbidden
handleAuthResSome xs = do
  logDebugN ("Allowed by:")
  traverse_ (logDebugN . showT) xs
  pure (authToken <$> xs)

hasZonePerm :: Show tok => [Authorization tok DomPat] -> T.Text -> T.Text -> GerdM tok
hasZonePerm perms srv zone = do
  zone' <- parseZone zone
  handleAuthRes1 (matchingZone srv zone' perms)

hasZonePerms :: Show tok => [Authorization tok DomPat] -> T.Text -> T.Text -> GerdM [tok]
hasZonePerms perms srv zone = do
  zone' <- parseZone zone
  handleAuthResSome (matchingZone srv zone' perms)

hasPerm :: (Show tok, Show pat) => [Authorization tok pat] -> T.Text -> GerdM tok
hasPerm perms srv = handleAuthRes1 (matchingSrv srv perms)

recordUpdatePats :: [Authorization DomTyPat DomPat] -> T.Text -> T.Text -> GerdM [DomTyPat]
recordUpdatePats perms srv zone = do
  zone' <- parseZone zone
  pure (authToken <$> matchingZone srv zone' perms)


guardedZones :: User -> PDNS.ZonesAPI AsGerd
guardedZones user = PDNS.ZonesAPI
    { PDNS.apiListZones     = \srv zone dnssec -> do
        mode <- hasPerm (permZoneList perms) srv
        zs <- runProxy (PDNS.listZones srv zone dnssec)
        case mode of
            Filtered   -> do
              wither (\z -> do
                         nam <- PDNS.zone_name z `notePanic` "missing zone name"
                         domTyPats <- recordUpdatePats (permZoneUpdateRecords perms) srv nam
                         filterZoneMaybe domTyPats z
                     ) zs
            Unfiltered -> pure zs

    , PDNS.apiCreateZone    = \srv rrset zone -> do
        hasPerm (permZoneCreate perms) srv
        runProxy (PDNS.createZone srv rrset zone)

    , PDNS.apiGetZone       = \srv zone rrs -> do
        perm <- hasZonePerm (permZoneView perms) srv zone
        z <- runProxy (PDNS.getZone srv zone rrs)
        case perm of
            Filtered   -> do
              domTyPats <- recordUpdatePats (permZoneUpdateRecords perms) srv zone
              filterZone domTyPats z
            Unfiltered -> pure z

    , PDNS.apiDeleteZone    = \srv zone -> do
        hasZonePerm (permZoneDelete perms) srv zone
        runProxy (PDNS.deleteZone srv zone)

    , PDNS.apiUpdateRecords = \srv zone rrs -> do
        domTyPats <- hasZonePerms (permZoneUpdateRecords perms) srv zone
        when (null (PDNS.rrsets rrs)) $ do
          logDebugN "zone record update: Record has no RRsets"

          -- Ensure we do not forward requests without RRSets to the upstream API.
          forbidden

        traverse_ (authorizeRecordUpdate domTyPats) (PDNS.rrsets rrs)

        runProxy (PDNS.updateRecords srv zone rrs)

    , PDNS.apiUpdateZone    = \srv zone zoneData -> do
        hasZonePerm (permZoneUpdate perms) srv zone
        runProxy (PDNS.updateZone srv zone zoneData)

    , PDNS.apiTriggerAxfr   = \srv zone -> do
        hasZonePerm (permZoneTriggerAxfr perms) srv zone
        runProxy (PDNS.triggerAxfr srv zone)

    , PDNS.apiNotifySlaves  = \srv zone -> do
        hasZonePerm (permZoneNotifySlaves perms) srv zone
        runProxy (PDNS.notifySlaves srv zone)

    , PDNS.apiGetZoneAxfr   = \srv zone -> do
        hasZonePerm (permZoneGetAxfr perms) srv zone
        runProxy (PDNS.getZoneAxfr srv zone)

    , PDNS.apiRectifyZone   = \srv zone -> do
        hasZonePerm (permZoneRectify perms) srv zone
        runProxy (PDNS.rectifyZone srv zone)
    }
  where
    perms :: Perms
    perms = uPerms user

guardedCryptokeys :: User -> PDNS.CryptokeysAPI AsGerd
guardedCryptokeys _ = PDNS.CryptokeysAPI
    { PDNS.apiListCryptokeys  = const2 forbidden
    , PDNS.apiCreateCryptokey = const3 forbidden
    , PDNS.apiGetCryptokey    = const3 forbidden
    , PDNS.apiUpdateCryptokey = const4 forbidden
    , PDNS.apiDeleteCryptokey = const3 forbidden
    }

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

showT :: Show a => a -> T.Text
showT = T.pack . show

-- | Version of 'filterZone' that produces Nothing if no RRSets are left.
filterZoneMaybe :: [DomTyPat] -> PDNS.Zone -> GerdM (Maybe PDNS.Zone)
filterZoneMaybe pats zone = do
  z <- filterZone pats zone
  if (null (PDNS.zone_rrsets z))
    then pure Nothing
    else pure (Just z)

(<+>) :: T.Text -> T.Text -> T.Text
l <+> r = l <> " " <> r

bracket :: T.Text -> T.Text
bracket t = "[" <> t <> "]"

pprRRSet :: PDNS.RRSet -> T.Text
pprRRSet rr = bracket (showT (PDNS.rrset_type rr) <+> PDNS.rrset_name rr)

-- | Given some elaborated domain permissions, filter out all RRSets for which we do not have matching domain permissions for.
filterZone :: [DomTyPat] -> PDNS.Zone -> GerdM PDNS.Zone
filterZone pats zone = do
    logDebugN ("Filtering zone: " <> fromMaybe "<unnamed" (PDNS.zone_name zone))

    filtered <- maybe (pure Nothing)
                      (fmap Just . wither go)
                      (PDNS.zone_rrsets zone)
    pure $ zone { PDNS.zone_rrsets = filtered }
  where
    go rr = do
      dom <- parseDom (PDNS.rrset_name rr)
      let ty = PDNS.rrset_type rr
      let matching = filter (matchesDomTyPat dom ty) pats

      case matching of
        [] -> do logDebugN ("Hiding record: " <> pprRRSet rr)
                 pure Nothing
        xs -> do logDebugN ("Allowing record " <> pprRRSet rr)
                 logDebugN ("Matching pattern:")
                 traverse_ (logDebugN . showT) xs
                 pure (Just rr)
forbidden :: GerdM a
forbidden = throwIO err403

unprocessableWhy :: T.Text -> GerdM a
unprocessableWhy why = throwIO err422 { errBody = TL.encodeUtf8 (TL.fromStrict why) }

notePanic :: Maybe a -> T.Text -> GerdM a
notePanic m t = maybe (logErrorN t >> throwIO err500) pure m
