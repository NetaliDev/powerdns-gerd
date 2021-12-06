{-# LANGUAGE ApplicativeDo     #-}
{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module PowerDNS.Gerd.Config
  ( Config(..)
  , loadConfig
  , configHelp
  )
where

import           Control.Arrow ((&&&))
import           Data.Maybe (fromMaybe)
import           Data.String (fromString)

import           Config.Schema
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Word (Word16)
import           Network.Wai.Handler.Warp (HostPreference)
import qualified Text.PrettyPrint as Pretty

import           Control.Monad (unless)
import           Data.Bifunctor (first)
import           Data.Foldable (for_)
import qualified Data.Map as M
import qualified Data.Set as S
import           Optics
import           PowerDNS.API.Zones
import           PowerDNS.Gerd.Permission
import           PowerDNS.Gerd.Permission.Optics
import           PowerDNS.Gerd.User
import           PowerDNS.Gerd.Utils
import           UnliftIO (MonadIO, liftIO)

data ConfigNonValidated = ConfigNonValidated
  { cfgnvUpstreamApiBaseUrl :: T.Text
  , cfgnvUpstreamApiKey :: T.Text
  , cfgnvListenAddress :: HostPreference
  , cfgnvListenPort :: Word16
  , cfgnvUsers :: [UserNonValidated]
  }

data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey :: T.Text
  , cfgListenAddress :: HostPreference
  , cfgListenPort :: Word16
  , cfgUsers :: M.Map Username User
  }


optSectionDefault' :: a -> T.Text -> ValueSpec a -> T.Text -> SectionsSpec a
optSectionDefault' def sect spec descr = fromMaybe def <$> optSection' sect spec descr

absRecordPermSpec :: ValueSpec (DomainPattern, AllowSpec)
absRecordPermSpec = sectionsSpec "abs-record-spec" $ do
  n <- reqSection' "name" domainPatSpec "The record name(s) that can be managed. Must be absolute with a trailing dot."
  t <- reqSection' "types" recordTypeSpec "The record types that can be managed."
  pure (n, t)

filteredPermissionSpec :: ValueSpec FilteredPermission
filteredPermissionSpec = Filtered <$ atomSpec "filtered"
                 <!> Unfiltered <$ atomSpec "unfiltered"

authorizationSpec :: ValueSpec (Authorization ())
authorizationSpec = Authorized () <$ atomSpec "permit"
                <!> Forbidden <$ atomSpec "forbid"

serverPermsSpec :: ValueSpec ServerPerms
serverPermsSpec = sectionsSpec "server-perms-spec" $ do
  spListServers <- optSectionDefault' Forbidden "listServers" authorizationSpec "Permission for `GET /servers`. Forbidden by default"
  spGetServer <- optSectionDefault' Forbidden "getServer" authorizationSpec "Permission for `GET /servers/:server_id`. Forbidden by default"
  spSearch <- optSectionDefault' Forbidden "search" authorizationSpec "Permission for `GET /servers/:server_id/search-data`. Forbidden by default"
  spFlushCache <- optSectionDefault' Forbidden "flushCache" authorizationSpec "Permission for `PUT /servers/:server_id/cache/flush` Forbidden by default"
  spStatistics <- optSectionDefault' Forbidden "statistics" authorizationSpec "Permission for `GET /servers/:server_id/statistics`. Forbidden by default"
  pure ServerPerms{..}

tsigkeyPermsSpec :: ValueSpec TSIGKeyPerms
tsigkeyPermsSpec = sectionsSpec "tsigkeys-perms-spec" $ do
  tspAny <- optSectionDefault' Forbidden "any" authorizationSpec "Permission for any tsigkey interaction"
  pure TSIGKeyPerms{..}

permSetSpec :: ValueSpec (PermSet Lookup)
permSetSpec = sectionsSpec "permset-spec" $ do
    psVersionsPerms <- optSectionDefault' (Authorized ()) "versions" authorizationSpec "Permission for (undocumented) `GET /api`. Allowed by default."
    psServersPerms <- optSectionDefault' serversForbidden "servers" serverPermsSpec "Permission for `/servers` endpoints. All forbidden by default."
    psZonePerms <- optSectionDefault' zonesForbidden "zones" zonePermsSpec "Permission for `/servers/:server_id/zones` endpoints. All forbidden by default."
    psTSIGKeyPerms <- optSectionDefault' tsigkeyForbidden "tsigkeys" tsigkeyPermsSpec "Permissions for `/servers/:server_id/tsigkeys` endpoints. All forbidden by default."
    pure PermSet{..}
  where
    tsigkeyForbidden = TSIGKeyPerms Forbidden
    serversForbidden = ServerPerms Forbidden Forbidden Forbidden Forbidden Forbidden
    zonesForbidden = ZonePerms [] (Lookup []) Forbidden Forbidden

metadataPermsSpec :: ValueSpec MetadataPerms
metadataPermsSpec = sectionsSpec "metadata-perms-spec" $ do
  mdAny <- optSectionDefault' Forbidden "any" authorizationSpec "Permission for any metadata interaction"
  pure MetadataPerms{..}

cryptokeyPermsSpec :: ValueSpec CryptokeyPerms
cryptokeyPermsSpec = sectionsSpec "cryptokey-perms-spec" $ do
  cpAny <- optSectionDefault' Forbidden "any" authorizationSpec "Permission for any cryptokey interaction"
  pure CryptokeyPerms{..}


perZonePermsSpec :: SectionsSpec PerZonePerms
perZonePermsSpec = do
  pzpDomainPerms <- optSectionDefault' [] "domains"
                                         (listSpec absRecordPermSpec)
                                         "List of editable domains"
  pzpViewZone <- optSectionDefault' Forbidden "view" (Authorized <$> filteredPermissionSpec) "Permission to view this zone, filtered or unfiltered. When unfiltered, this user can see all records of a zone in the GET endpoint. When filtered, the result will be filtered to only include RRSets the user can also modify. Forbidden by default."
  pzpDeleteZone <- optSectionDefault' Forbidden "delete" authorizationSpec "Permission to delete this zone. Forbidden by default."
  pzpUpdateZone <- optSectionDefault' Forbidden "update" authorizationSpec "Permission to update this zone. Forbidden by default."
  pzpTriggerAxfr <- optSectionDefault' Forbidden "triggerAxfr" authorizationSpec "Permission to trigger a zone transfer on a slave. Forbidden by default."
  pzpNotifySlaves <- optSectionDefault' Forbidden "notifySlaves" authorizationSpec "Permission to notify slaves. Forbidden by default."
  pzpGetZoneAxfr <- optSectionDefault' Forbidden "getAxfr" authorizationSpec "Permission to obtain a zone transfer in AXFR format. Forbidden by default."
  pzpRectifyZone <- optSectionDefault' Forbidden "rectifyZone" authorizationSpec "Permission to rectify the zone. Forbidden by default."
  pzpMetadataPerms <- optSectionDefault' metadataForbidden "metadataPerms" metadataPermsSpec "Permissions for metadata access. All forbidden by default."
  pzpCryptokeysPerms <- optSectionDefault' cryptokeyForbidden "cryptokeyPerms" cryptokeyPermsSpec "Permissions for cryptokeys access. All forbidden by default."

  pure PerZonePerms{..}

  where
    metadataForbidden = MetadataPerms Forbidden
    cryptokeyForbidden = CryptokeyPerms Forbidden

zoneMapItemSpec :: ValueSpec (ZoneId, PerZonePerms)
zoneMapItemSpec = sectionsSpec "zone" $ do
  name <- reqSection' "zone" zoneIdSpec "The name of the zone"
  perms <- perZonePermsSpec
  pure (name, perms)

recordTypeSpec :: ValueSpec AllowSpec
recordTypeSpec = MayModifyAnyRecordType <$ atomSpec "any"
             <!> MayModifyRecordType <$> listSpec recordAtomSpec

domainPatSpec :: ValueSpec DomainPattern
domainPatSpec = customSpec "Absolute domain (with trailing dot). A leading wildcard like \"*.foo\" or \"*\" is allowed"
                            textSpec
                            (first T.pack . parseDomainPattern)

zoneIdSpec :: ValueSpec ZoneId
zoneIdSpec = ZoneId <$> customSpec "Zone name (with trailing dot)."
                        textSpec
                        (first T.pack . parseAbsDomain)

recordAtomSpec :: ValueSpec RecordType
recordAtomSpec =    A          <$ atomSpec "A"
                <!> AAAA       <$ atomSpec "AAAA"
                <!> AFSDB      <$ atomSpec "AFSDB"
                <!> ALIAS      <$ atomSpec "ALIAS"
                <!> APL        <$ atomSpec "APL"
                <!> CAA        <$ atomSpec "CAA"
                <!> CERT       <$ atomSpec "CERT"
                <!> CDNSKEY    <$ atomSpec "CDNSKEY"
                <!> CDS        <$ atomSpec "CDS"
                <!> CNAME      <$ atomSpec "CNAME"
                <!> DNSKEY     <$ atomSpec "DNSKEY"
                <!> DNAME      <$ atomSpec "DNAME"
                <!> DS         <$ atomSpec "DS"
                <!> HINFO      <$ atomSpec "HINFO"
                <!> KEY        <$ atomSpec "KEY"
                <!> LOC        <$ atomSpec "LOC"
                <!> MX         <$ atomSpec "MX"
                <!> NAPTR      <$ atomSpec "NAPTR"
                <!> NS         <$ atomSpec "NS"
                <!> NSEC       <$ atomSpec "NSEC"
                <!> NSEC3      <$ atomSpec "NSEC3"
                <!> NSEC3PARAM <$ atomSpec "NSEC3PARAM"
                <!> OPENPGPKEY <$ atomSpec "OPENPGPKEY"
                <!> PTR        <$ atomSpec "PTR"
                <!> RP         <$ atomSpec "RP"
                <!> RRSIG      <$ atomSpec "RRSIG"
                <!> SOA        <$ atomSpec "SOA"
                <!> SPF        <$ atomSpec "SPF"
                <!> SSHFP      <$ atomSpec "SSHFP"
                <!> SRV        <$ atomSpec "SRV"
                <!> TKEY       <$ atomSpec "TKEY"
                <!> TSIG       <$ atomSpec "TSIG"
                <!> TLSA       <$ atomSpec "TLSA"
                <!> SMIMEA     <$ atomSpec "SMIMEA"
                <!> TXT        <$ atomSpec "TXT"
                <!> URI        <$ atomSpec "URI"
                <!> A6         <$ atomSpec "A6"
                <!> DHCID      <$ atomSpec "DHCID"
                <!> DLV        <$ atomSpec "DLV"
                <!> EUI48      <$ atomSpec "EUI48"
                <!> EUI64      <$ atomSpec "EUI64"
                <!> IPSECKEY   <$ atomSpec "IPSECKEY"
                <!> KX         <$ atomSpec "KX"
                <!> MAILA      <$ atomSpec "MAILA"
                <!> MAILB      <$ atomSpec "MAILB"
                <!> MINFO      <$ atomSpec "MINFO"
                <!> MR         <$ atomSpec "MR"
                <!> RKEY       <$ atomSpec "RKEY"
                <!> SIG        <$ atomSpec "SIG"
                <!> WKS        <$ atomSpec "WKS"

hostPrefSpec :: ValueSpec HostPreference
hostPrefSpec = fromString . T.unpack <$> textSpec

configSpec :: ValueSpec ConfigNonValidated
configSpec = sectionsSpec "top-level" $ do
  cfgnvUpstreamApiBaseUrl <- reqSection "upstreamApiBaseUrl" "The base URL of the upstream PowerDNS API."
  cfgnvUpstreamApiKey <- reqSection "upstreamApiKey" "The upstream X-API-Key secret"
  cfgnvListenAddress <- reqSection' "listenAddress" hostPrefSpec "The IP address the proxy will bind on"
  cfgnvListenPort <- reqSection "listenPort" "The TCP port the proxy will bind on"
  cfgnvUsers <- reqSection' "users" (listSpec userSpec) "Configured users"
  pure ConfigNonValidated{..}

zonePermsSpec :: ValueSpec (ZonePerms Lookup)
zonePermsSpec = sectionsSpec "zones-spec" $ do
  zpPerZonePerms <- Lookup <$> optSectionDefault' []
                                                "zones"
                                                (listSpec zoneMapItemSpec)
                                                "Zone-specific permissions"

  zpUndestrictedDomainPerms <- optSectionDefault' []
                                       "domains"
                                       (listSpec absRecordPermSpec)
                                      "Global domain permissions"
  zpCreateZone <- optSectionDefault' Forbidden "createZone" authorizationSpec "Permission to create zones. Forbidden by default."
  zpListZones <- optSectionDefault' Forbidden "listZones" (Authorized <$> filteredPermissionSpec) "Permission to list zones, filtered or unfiltered. When unfiltered, this user can see all zones including all RRSets. When filtered, the result will be filtered to only include zones the user has any domain permissions on, and then each zone is filtered to include only those RRSets."
  pure ZonePerms{..}

userSpec :: ValueSpec UserNonValidated
userSpec = sectionsSpec "user-spec" $ do
  _unvName <- Username <$> reqSection "name" "The name of the API user"
  _unvPassHash <- reqSection' "passHash"
                            (T.encodeUtf8 <$> textSpec)
                            "Argon2id hash of the secret as a string in the original reference format, e.g.: $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
  _unvPerms <- reqSection' "permissions" permSetSpec "Permissions for this user"

  pure UserNonValidated{..}

loadConfig :: MonadIO m => FilePath -> m Config
loadConfig path = liftIO $ do
  cfg <- loadValueFromFile configSpec path
  validate cfg

configHelp :: String
configHelp = Pretty.render (generateDocs configSpec)

validate :: ConfigNonValidated -> IO Config
validate cfg = do
  validateUniqueUsers cfg
  users <- traverse validateUser (cfgnvUsers cfg)

  pure Config{ cfgUpstreamApiBaseUrl = cfgnvUpstreamApiBaseUrl cfg
             , cfgUpstreamApiKey = cfgnvUpstreamApiKey cfg
             , cfgListenAddress = cfgnvListenAddress cfg
             , cfgListenPort = cfgnvListenPort cfg
             , cfgUsers = M.fromList ((_uName &&& id) <$> users)
             }

validatePermSet :: PermSet Lookup -> IO (PermSet M.Map)
validatePermSet ups = do
  let zones = ups ^. zonePerms %  perZonePerms % to runLookup
      dups = duplicates (fst <$> zones)

  unless (null dups) $
    fail ("Duplicate zones: " <> T.unpack (T.intercalate ", " (getZone <$> dups)))

  for_ zones $ \(ZoneId zone, perms) -> do
    for_ (pzpDomainPerms perms) $ \(pat, _allow) -> do
        let pat' = pprDomainPattern pat
        unless (zone `T.isSuffixOf` pat') $
            fail ("Pattern is out of zone " <> T.unpack (quoted zone) <> ": " <> T.unpack pat')

  pure (ups & zonePerms % perZonePerms .~ M.fromList zones)

validateUser :: UserNonValidated -> IO User
validateUser unv = do
  perms <- validatePermSet (_unvPerms unv)
  pure User{ _uName = _unvName unv
           , _uPassHash = _unvPassHash unv
           , _uPerms = perms }


duplicates :: Ord a => [a] -> [a]
duplicates = go mempty
  where
    go _seen []    = []
    go seen (x:xs) | x `S.member` seen
                   = x : go seen xs

                   | otherwise
                   = go (S.insert x seen) xs


validateUniqueUsers :: ConfigNonValidated -> IO ()
validateUniqueUsers cfg = do
  let dups = duplicates (_unvName <$> cfgnvUsers cfg)
  unless (null dups) $
    fail ("Duplicate users: " <> T.unpack (T.intercalate ", " (getUsername <$> dups)))
