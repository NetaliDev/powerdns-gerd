-- |
-- Module: PowerDNS.Gerd.Server.Endpoints
-- Description: Endpoints of the Gerd Proxy
--
-- This module defines the endpoint handlers that implement the authorization
-- and forwarding of powerdns-gerd.
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators     #-}
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
import           Data.Foldable (toList, traverse_)
import           Data.Maybe (catMaybes, fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TL

import           GHC.TypeLits (KnownSymbol)
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


wither :: Applicative f => (a -> f (Maybe b)) -> [a] -> f [b]
wither f t = catMaybes <$> traverse f t


-- | Ensure the user has sufficient permissions for this record update
validateRecordUpdate :: [DomTyPat] -> PDNS.RRSet -> GerdM ()
validateRecordUpdate pats rrset = do
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

type SrvSelector tok tag = AnySelector (Authorization tok ()) tag
type ZoneSelector tok pat tag = AnySelector (Authorization tok pat) tag
type SimpleSelector tag = AnySelector SimpleAuthorization tag
type AnySelector what tag = Perms -> Maybe [what] `WithDoc` tag

authorizeZoneEndpoint :: (KnownSymbol tag, Show tok) => User -> ZoneSelector tok DomPat tag -> T.Text -> T.Text -> GerdM tok
authorizeZoneEndpoint user sel srv zone = do
  zone' <- parseZone zone
  perms <- authorizeEndpoint__ user sel
  handleAuthRes1 (matchingZone srv zone' perms)

authorizeZoneEndpoints :: (KnownSymbol tag, Show tok) => User -> ZoneSelector tok DomPat tag -> T.Text -> T.Text -> GerdM [tok]
authorizeZoneEndpoints user sel srv zone = do
  zone' <- parseZone zone
  perms <- authorizeEndpoint__ user sel
  handleAuthResSome (matchingZone srv zone' perms)

authorizeEndpoint__ :: KnownSymbol tag => User -> AnySelector what tag -> GerdM [what]
authorizeEndpoint__ user sel = do
  case withoutDoc (sel (uPerms user)) of
    Nothing -> do
      logWarnN ("Permission denied for: " <> describe sel)
      forbidden
    Just perms -> do
      logDebugN ("Endpoint access granted for:" <> describe sel)
      pure perms

authorizeSimpleEndpoint :: KnownSymbol tag => User -> SimpleSelector tag -> GerdM ()
authorizeSimpleEndpoint user sel = () <$ authorizeEndpoint__ user sel

authorizeSrvEndpoint :: (KnownSymbol tag, Show tok) => User -> SrvSelector tok tag -> T.Text -> GerdM tok
authorizeSrvEndpoint user sel srv = do
  perms <- authorizeEndpoint__ user sel
  handleAuthRes1 (matchingSrv srv perms)

recordUpdatePats :: [Authorization DomTyPat DomPat] -> T.Text -> T.Text -> GerdM [DomTyPat]
recordUpdatePats perms srv zone = do
  zone' <- parseZone zone
  pure (authToken <$> matchingZone srv zone' perms)

guardedVersions :: User -> PDNS.VersionsAPI AsGerd
guardedVersions user = PDNS.VersionsAPI
  { PDNS.apiListVersions = do
      authorizeSimpleEndpoint user permApiVersions
      runProxy PDNS.listVersions
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
guardedZones user = PDNS.ZonesAPI
    { PDNS.apiListZones     = \srv zone dnssec -> do
        mode <- authorizeSrvEndpoint user permZoneList srv
        zs <- runProxy (PDNS.listZones srv zone dnssec)
        case mode of
            Filtered   -> do
              wither (\z -> do
                         nam <- PDNS.zone_name z `notePanic` "missing zone name"
                         perms <- authorizeEndpoint__ user permZoneUpdateRecords
                         domTyPats <- recordUpdatePats perms srv nam
                         case domTyPats of
                           [] -> pure Nothing
                           _  -> Just <$> filterZone domTyPats z
                     ) zs
            Unfiltered -> pure zs

    , PDNS.apiCreateZone    = \srv rrset zone -> do
        authorizeSrvEndpoint user permZoneCreate srv
        runProxy (PDNS.createZone srv rrset zone)

    , PDNS.apiGetZone       = \srv zone rrs -> do
        perm <- authorizeZoneEndpoint user permZoneView srv zone
        z <- runProxy (PDNS.getZone srv zone rrs)
        case perm of
            Filtered   -> do
              domTyPats <- do
                perms <- authorizeEndpoint__ user permZoneUpdateRecords
                recordUpdatePats perms srv zone
              filterZone domTyPats z
            Unfiltered -> pure z

    , PDNS.apiDeleteZone    = \srv zone -> do
        authorizeZoneEndpoint user permZoneDelete srv zone
        runProxy (PDNS.deleteZone srv zone)

    , PDNS.apiUpdateRecords = \srv zone rrs -> do
        domTyPats <- authorizeZoneEndpoints user permZoneUpdateRecords srv zone
        when (null (PDNS.rrsets rrs)) $ do
          logDebugN "zone record update: Record has no RRsets"

          -- Ensure we do not forward requests without RRSets to the upstream API.
          forbidden

        traverse_ (validateRecordUpdate domTyPats) (PDNS.rrsets rrs)

        runProxy (PDNS.updateRecords srv zone rrs)

    , PDNS.apiUpdateZone    = \srv zone zoneData -> do
        authorizeZoneEndpoint user permZoneUpdate srv zone
        runProxy (PDNS.updateZone srv zone zoneData)

    , PDNS.apiTriggerAxfr   = \srv zone -> do
        authorizeZoneEndpoint user permZoneTriggerAxfr srv zone
        runProxy (PDNS.triggerAxfr srv zone)

    , PDNS.apiNotifySlaves  = \srv zone -> do
        authorizeZoneEndpoint user permZoneNotifySlaves srv zone
        runProxy (PDNS.notifySlaves srv zone)

    , PDNS.apiGetZoneAxfr   = \srv zone -> do
        authorizeZoneEndpoint user permZoneGetAxfr srv zone
        runProxy (PDNS.getZoneAxfr srv zone)

    , PDNS.apiRectifyZone   = \srv zone -> do
        authorizeZoneEndpoint user permZoneRectify srv zone
        runProxy (PDNS.rectifyZone srv zone)
    }

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
