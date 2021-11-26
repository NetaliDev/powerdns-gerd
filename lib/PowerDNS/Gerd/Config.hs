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

import           Control.Exception (SomeException, displayException)
import           Data.Maybe (fromMaybe)
import           Data.String (fromString)
import           System.Exit (exitFailure)
import           System.IO (hPutStrLn, stderr)

import           Config.Schema
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Word (Word16)
import           Network.Wai.Handler.Warp (HostPreference)
import qualified Text.PrettyPrint as Pretty
import           UnliftIO.Exception (catch)

import           Data.Bifunctor (first)
import qualified Data.Map as M
import           PowerDNS.API.Zones
import           PowerDNS.Gerd.Permission
import           PowerDNS.Gerd.User
import           PowerDNS.Gerd.Utils

data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey :: T.Text
  , cfgListenAddress :: HostPreference
  , cfgListenPort :: Word16
  , cfgUsers :: [User]
  }

optSectionDefault' :: a -> T.Text -> ValueSpec a -> T.Text -> SectionsSpec a
optSectionDefault' def sect spec descr = fromMaybe def <$> optSection' sect spec descr

absRecordPermSpec :: ValueSpec (DomainPattern, AllowSpec)
absRecordPermSpec = sectionsSpec "abs-record-spec" $ do
  n <- reqSection' "name" domainPatSpec "The record name(s) that can be managed. Must be absolute with a trailing dot."
  t <- reqSection' "types" recordTypeSpec "The record types that can be managed."
  pure (n, t)

zoneMapSpec :: ValueSpec (M.Map ZoneId ZonePermissions)
zoneMapSpec = M.fromList <$> listSpec zoneMapItemSpec

viewPermissionSpec :: ValueSpec ViewPermission
viewPermissionSpec = Filtered <$ atomSpec "filtered"
                 <!> Unfiltered <$ atomSpec "unsafeUnfiltered"

authorizationSpec :: ValueSpec Authorization
authorizationSpec = Authorized <$ atomSpec "permit"

zoneMapItemSpec :: ValueSpec (ZoneId, ZonePermissions)
zoneMapItemSpec = sectionsSpec "zone" $ do
  zoneName <- reqSection' "zone" zoneIdSpec "The name of the zone"

  zpDomainPerms <- optSectionDefault' [] "domains"
                                                 (listSpec absRecordPermSpec)
                                                 "List of records permissions"
  zpViewZone <- optSection' "view" viewPermissionSpec "Permission to view this zone, filtered or unfiltered. When unfiltered, this user can see all records of a zone in the GET endpoint. When filtered, the result will be filtered to only include RRSets the user can also modify. Forbidden by default."
  zpDeleteZone <- optSectionDefault' Forbidden "delete" authorizationSpec "Permission to delete this zone. Forbidden by default."
  zpUpdateZone <- optSectionDefault' Forbidden "update" authorizationSpec "Permission to update this zone. Forbidden by default."
  zpTriggerAxfr <- optSectionDefault' Forbidden "triggerAxfr" authorizationSpec "Permission to trigger a zone transfer on a slave. Forbidden by default."
  zpNotifySlaves <- optSectionDefault' Forbidden "notifySlaves" authorizationSpec "Permission to notify slaves. Forbidden by default."
  zpGetZoneAxfr <- optSectionDefault' Forbidden "getAxfr" authorizationSpec "Permission to obtain a zone transfer in AXFR format. Forbidden by default."
  zpRectifyZone <- optSectionDefault' Forbidden "rectifyZone" authorizationSpec "Permission to rectify the zone. Forbidden by default."

  pure (zoneName, ZonePermissions{..})

recordTypeSpec :: ValueSpec AllowSpec
recordTypeSpec = MayModifyAnyRecordType <$ atomSpec "any"
             <!> MayModifyRecordType <$> listSpec recordAtomSpec

domainPatSpec :: ValueSpec DomainPattern
domainPatSpec = DomainPattern [DomGlobStar] <$ atomSpec "any"
            <!> customSpec "Absolute domain (with trailing dot). A leading wildcard like \"*.foo\" or \"*\" is allowed"
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

configSpec :: ValueSpec Config
configSpec = sectionsSpec "top-level" $ do
  cfgUpstreamApiBaseUrl <- reqSection "upstreamApiBaseUrl" "The base URL of the upstream PowerDNS API."
  cfgUpstreamApiKey <- reqSection "upstreamApiKey" "The upstream X-API-Key secret"
  cfgListenAddress <- reqSection' "listenAddress" hostPrefSpec "The IP address the proxy will bind on"
  cfgListenPort <- reqSection "listenPort" "The TCP port the proxy will bind on"
  cfgUsers <- reqSection' "users" (listSpec userSpec) "Configured users"
  pure Config{..}

userSpec :: ValueSpec User
userSpec = sectionsSpec "user" $ do
  _uName <- reqSection "name" "The name of the API user"
  _uPassHash <- reqSection' "passHash"
                            (T.encodeUtf8 <$> textSpec)
                            "Argon2id hash of the secret as a string in the original reference format, e.g.: $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
  _uZonePerms <- optSectionDefault' mempty
                                    "zones"
                                    (zoneMapSpec)
                                    "Zone-specific permissions"
  _uRecordPerms <- optSectionDefault' []
                                    "domains"
                                    (listSpec absRecordPermSpec)
                                    "Global domain permissions"

  pure User{..}

loadConfig :: FilePath -> IO Config
loadConfig path = loadValueFromFile configSpec path `catch` onError
  where
    onError :: SomeException -> IO a
    onError ex = do
      hPutStrLn stderr "Error while parsing config"
      hPutStrLn stderr (displayException ex)
      exitFailure

configHelp :: String
configHelp = Pretty.render (generateDocs configSpec)
