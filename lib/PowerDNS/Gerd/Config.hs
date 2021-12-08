{-# LANGUAGE ApplicativeDo       #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE OverloadedLabels    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE ScopedTypeVariables #-}
module PowerDNS.Gerd.Config
  ( Config(..)
  , loadConfig
  , configHelp
  )
where

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
import qualified Data.Set as S
import           PowerDNS.API.Zones
import           PowerDNS.Gerd.Permission
import           PowerDNS.Gerd.User
import           PowerDNS.Gerd.Utils
import           UnliftIO (MonadIO, liftIO)

data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey :: T.Text
  , cfgListenAddress :: HostPreference
  , cfgListenPort :: Word16
  , cfgDefaultPerms :: Perms
  , cfgUsers :: [(Username, User)]
  }

optSectionDefault' :: a -> T.Text -> ValueSpec a -> T.Text -> SectionsSpec a
optSectionDefault' def sect spec descr = fromMaybe def <$> optSection' sect spec descr

simpleAuthSpec :: ValueSpec [SimpleAuthorization]
simpleAuthSpec = [] <$ atomSpec "forbid"

auth''spec :: ValueSpec [Authorization'']
auth''spec = (pure <$> permit) <!> oneOrList
    (sectionsSpec "server-authorization-spec" $ do
      authServer <- reqSection' "server" textSpec "Matching this server. Defaults to localhost"
      authPattern <- pure ()
      authToken <- pure ()
      pure Authorization{..})
  where
    permit = Authorization "localhost" () () <$ atomSpec "permit"

anyDomPat :: DomPat
anyDomPat = DomPat [DomGlobStar]

permZoneListSpec :: ValueSpec [Authorization Filtered ()]
permZoneListSpec = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-list-spec" $ do
        authServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        authPattern <- pure ()
        authToken <- reqSection' "type" filteredSpec "Whether or not records will be filtered using zoneUpdateRecords permissions"
        pure Authorization{..})
  where
    permit = Authorization "localhost" () Unfiltered <$ atomSpec "permit"
    filtered = Authorization "localhost" () Filtered <$ atomSpec "filtered"

permZoneViewSpec :: ValueSpec [Authorization Filtered DomPat]
permZoneViewSpec = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-view-spec" $ do
        authServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        authPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        authToken <- reqSection' "type" filteredSpec "Whether or not records in all zones will be filtered using zoneUpdateRecords permissions. If a zone has no visible records, it will be omitted entirely"
        pure Authorization{..})
  where
    permit = Authorization "localhost" anyDomPat Unfiltered <$ atomSpec "permit"
    filtered = Authorization "localhost" anyDomPat Filtered <$ atomSpec "filtered"

permZoneSpec :: ValueSpec [Authorization' DomPat]
permZoneSpec = (pure <$> permit) <!> oneOrList
    (sectionsSpec "perm-zone-spec" $ do
        authServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        authPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        authToken <- pure ()
        pure Authorization{..})
  where
    permit = Authorization "localhost" anyDomPat () <$ atomSpec "permit"

domTyPatSpec :: SectionsSpec DomTyPat
domTyPatSpec = do
  domPat <- reqSection' "domain" domPatSpec "Matching any of these domains"
  recTyPat <- reqSection' "types" recTyPatSpec "Matching any of these record types"
  pure (domPat, recTyPat)

permZoneUpdateRecordsSpec :: ValueSpec (Authorization DomTyPat DomPat)
permZoneUpdateRecordsSpec = sectionsSpec "perm-zone-update-records-spec" $ do
  authServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
  authPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
  authToken <- domTyPatSpec
  pure Authorization{..}

permsSpec :: ValueSpec Perms
permsSpec = sectionsSpec "perms-spec" $ do
    permApiVersions       <- Tagged <$> optSection' "apiVersions" simpleAuthSpec (annotationFor permApiVersions)
    permServerList        <- Tagged <$> optSection' "serverList" auth''spec (annotationFor permServerList)
    permServerView        <- Tagged <$> optSection' "serverView" auth''spec (annotationFor permServerView)
    permSearch            <- Tagged <$> optSection' "search" auth''spec (annotationFor permSearch)
    permFlushCache        <- Tagged <$> optSection' "flushCache" auth''spec (annotationFor permFlushCache)
    permStatistics        <- Tagged <$> optSection' "statistics" auth''spec (annotationFor permStatistics)
    permZoneCreate        <- Tagged <$> optSection' "zoneCreate" auth''spec (annotationFor permZoneCreate)
    permZoneList          <- Tagged <$> optSection' "zoneList" permZoneListSpec (annotationFor permZoneList)
    permZoneView          <- Tagged <$> optSection' "zoneView" permZoneViewSpec (annotationFor permZoneView)
    permZoneUpdate        <- Tagged <$> optSection' "zoneUpdate" permZoneSpec (annotationFor permZoneUpdate)
    permZoneUpdateRecords <- Tagged <$> optSection' "zoneUpdateRecords" (oneOrList permZoneUpdateRecordsSpec) (annotationFor permZoneUpdateRecords)
    permZoneDelete        <- Tagged <$> optSection' "zoneDelete" permZoneSpec (annotationFor permZoneDelete)
    permZoneTriggerAxfr   <- Tagged <$> optSection' "zoneTriggerAxfr" permZoneSpec (annotationFor permZoneTriggerAxfr)
    permZoneGetAxfr       <- Tagged <$> optSection' "zoneGetAxfr" permZoneSpec (annotationFor permZoneGetAxfr)
    permZoneNotifySlaves  <- Tagged <$> optSection' "zoneNotifySlaves" permZoneSpec (annotationFor permZoneNotifySlaves)
    permZoneRectify       <- Tagged <$> optSection' "zoneRectify" permZoneSpec (annotationFor permZoneRectify)
    permZoneMetadata      <- Tagged <$> optSection' "zoneMetadata" permZoneSpec (annotationFor permZoneMetadata)
    permZoneCryptokeys    <- Tagged <$> optSection' "zoneCryptokeys" permZoneSpec (annotationFor permZoneCryptokeys)
    permTSIGKeyList       <- Tagged <$> optSection' "tsigKeyList" auth''spec (annotationFor permTSIGKeyList)
    permTSIGKeyCreate     <- Tagged <$> optSection' "tsigKeyCreate" auth''spec (annotationFor permTSIGKeyCreate)
    permTSIGKeyView       <- Tagged <$> optSection' "tsigKeyView" auth''spec (annotationFor permTSIGKeyView)
    permTSIGKeyUpdate     <- Tagged <$> optSection' "tsigKeyUpdate" auth''spec (annotationFor permTSIGKeyUpdate)
    permTSIGKeyDelete     <- Tagged <$> optSection' "tsigKeyDelete" auth''spec (annotationFor permTSIGKeyDelete)

    pure Perms{..}
  where
    annotationFor sel = "Permission for " <> describe sel

filteredSpec :: ValueSpec Filtered
filteredSpec = Filtered <$ atomSpec "filtered"
           <!> Unfiltered <$ atomSpec "unfiltered"

recTyPatSpec :: ValueSpec RecTyPat
recTyPatSpec = namedSpec "record-type-spec" $
                 AnyRecordType <$ atomSpec "any"
             <!> AnyOf <$> oneOrList recordAtomSpec

domPatSpec :: ValueSpec DomPat
domPatSpec = customSpec "Absolute domain (with trailing dot). A leading wildcard like \"*.foo\" or \"*\" is allowed"
                            textSpec
                            (first T.pack . parseDomPat)

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

configSpec :: ValueSpec Config
configSpec = sectionsSpec "top-level" $ do
  cfgUpstreamApiBaseUrl <- reqSection "upstreamApiBaseUrl" "The base URL of the upstream PowerDNS API."
  cfgUpstreamApiKey <- reqSection "upstreamApiKey" "The upstream X-API-Key secret"
  cfgListenAddress <- reqSection' "listenAddress" hostPrefSpec "The IP address the proxy will bind on"
  cfgListenPort <- reqSection "listenPort" "The TCP port the proxy will bind on"
  cfgUsers <- reqSection' "users" (listSpec userSpec) "API users"
  cfgDefaultPerms <- optSectionDefault' allForbidden "defaultPerms" permsSpec "Default permissions. If a specific permission is not set under a user, If unset, all endpoints except API listing are forbidden by default."
  pure Config{..}

allForbidden :: Perms
allForbidden = Perms
  { permApiVersions       = Tagged (Just [SimpleAuthorization])
  , permServerList        = Tagged Nothing
  , permServerView        = Tagged Nothing
  , permSearch            = Tagged Nothing
  , permFlushCache        = Tagged Nothing
  , permStatistics        = Tagged Nothing
  , permZoneCreate        = Tagged Nothing
  , permZoneList          = Tagged Nothing
  , permZoneView          = Tagged Nothing
  , permZoneUpdate        = Tagged Nothing
  , permZoneUpdateRecords = Tagged Nothing
  , permZoneDelete        = Tagged Nothing
  , permZoneTriggerAxfr   = Tagged Nothing
  , permZoneGetAxfr       = Tagged Nothing
  , permZoneNotifySlaves  = Tagged Nothing
  , permZoneRectify       = Tagged Nothing
  , permZoneMetadata      = Tagged Nothing
  , permZoneCryptokeys    = Tagged Nothing
  , permTSIGKeyList       = Tagged Nothing
  , permTSIGKeyCreate     = Tagged Nothing
  , permTSIGKeyView       = Tagged Nothing
  , permTSIGKeyUpdate     = Tagged Nothing
  , permTSIGKeyDelete     = Tagged Nothing
  }

userSpec :: ValueSpec (Username, User)
userSpec = sectionsSpec "user-spec" $ do
  uName <- Username <$> reqSection "name" "The name of the API user"
  uPassHash <- reqSection' "passHash"
                            (T.encodeUtf8 <$> textSpec)
                            "Argon2id hash of the secret as a string in the original reference format, e.g.: $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
  uPerms <- reqSection' "permissions" permsSpec "Permissions for this user"

  pure (uName, User{..})

loadConfig :: MonadIO m => FilePath -> m Config
loadConfig path = liftIO $ do
  cfg <- loadValueFromFile configSpec path
  validate cfg
  pure cfg

configHelp :: String
configHelp = Pretty.render (generateDocs configSpec)

validate :: Config -> IO ()
validate cfg = do
  validateUniqueUsers cfg

duplicates :: Ord a => [a] -> [a]
duplicates = go mempty
  where
    go _seen []    = []
    go seen (x:xs) | x `S.member` seen
                   = x : go seen xs

                   | otherwise
                   = go (S.insert x seen) xs


validateUniqueUsers :: Config -> IO ()
validateUniqueUsers cfg = do
  let dups = duplicates (fst <$> cfgUsers cfg)
  unless (null dups) $
    fail ("Duplicate users: " <> T.unpack (T.intercalate ", " (getUsername <$> dups)))
