{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DataKinds #-}
module PowerDNS.Guard.Config
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
import           Data.Word (Word16)
import qualified Data.Text.Encoding as T
import           UnliftIO.Exception (catch)
import           Network.Wai.Handler.Warp (HostPreference)
import qualified Text.PrettyPrint as Pretty

import           PowerDNS.Guard.Account
import PowerDNS.Guard.Permission
import PowerDNS.API.Zones
import qualified Data.Map as M
import Data.Bifunctor (first)
import PowerDNS.Guard.Utils

data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey :: T.Text
  , cfgListenAddress :: HostPreference
  , cfgListenPort :: Word16
  , cfgAccounts :: [Account]
  }

optSectionDefault' :: a -> T.Text -> ValueSpec a -> T.Text -> SectionsSpec a
optSectionDefault' def sect spec descr = fromMaybe def <$> optSection' sect spec descr

absRecordPermSpec :: ValueSpec (DomainSpec Absolute, DomainPermission)
absRecordPermSpec = sectionsSpec "abs-record-spec" $ do
  n <- reqSection' "name" absDomainSpec "The record name(s) that can be managed. Must be absolute with a trailing dot."
  t <- reqSection' "types" recordTypeSpec "The record types that can be managed."
  pure (n, t)

zoneRecordPermSpec :: ValueSpec (DomainSpec Relative, DomainPermission)
zoneRecordPermSpec = sectionsSpec "zone-record-spec" $ do
  n <- reqSection' "name" relDomainSpec "The record name(s) that can be managed. Must be relative to the zone name."
  t <- reqSection' "types" recordTypeSpec "The record types that can be managed."
  pure (n, t)

zonePermSpec :: ValueSpec (ZoneId, PermissionList Relative)
zonePermSpec = sectionsSpec "zone-permission" $ do
  zone <- reqSection' "zone" (ZoneId <$> textSpec) "DNS name of the zone"
  perms <- optSectionDefault' []
                                         "recordPerms"
                                         (listSpec zoneRecordPermSpec)
                                         "List of records the user can manage in this zone"

  pure (zone, perms)

zonePermMapSpec :: ValueSpec (M.Map ZoneId (PermissionList Relative))
zonePermMapSpec = M.fromList <$> listSpec zonePermSpec

recordTypeSpec :: ValueSpec DomainPermission
recordTypeSpec = MayModifyAnyRecordType <$ atomSpec "any"
             <!> MayModifyRecordType <$> listSpec recordAtomSpec

relDomainSpec :: ValueSpec (DomainSpec Relative)
relDomainSpec = customSpec "Absolute domain (with trailing dot). A leading wildcard like \"*.foo\" or \"*\" is allowed"
                           textSpec
                           (first T.pack . parseRelDomainSpec)

absDomainSpec :: ValueSpec (DomainSpec Absolute)
absDomainSpec = customSpec "Relative domain (without trailing dot). A leading wildcard like \"*.foo\" or \"*\" is allowed"
                            textSpec
                            (first T.pack . parseAbsDomainSpec)

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
  cfgAccounts <- reqSection' "accounts" (listSpec accountSpec) "Configured accounts"
  pure Config{..}

accountSpec :: ValueSpec Account
accountSpec = sectionsSpec "account" $ do
  _acName <- reqSection "name" "The name of the API account"
  _acPassHash <- reqSection' "passHash"
                            (T.encodeUtf8 <$> textSpec)
                            "Argon2id hash of the secret as a string in the original reference format, e.g.: $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
  _acZonePerms <- optSectionDefault' mempty
                                    "zonePerms"
                                    (zonePermMapSpec)
                                    "Whether or not the account may list all zones of the server"
  _acRecordPerms <- optSectionDefault' []
                                    "recordPerms"
                                    (listSpec absRecordPermSpec)
                                    "Record permissions of absolute domains. This will grant a permission irrespective of the containing domain."

  pure Account{..}

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
