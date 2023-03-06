-- |
-- Module: PowerDNS.Gerd.Config
-- Description: Config loading and specification
--
-- This module contains the config format specification and loading code.
--
{-# LANGUAGE ApplicativeDo     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module PowerDNS.Gerd.Config
  ( Config(..)
  , loadConfig
  , configHelp
  , ApiKeyType(..)
  )
where

import           Data.Functor (($>))
import           Data.Maybe (fromMaybe)
import           Data.String (fromString)
import           Text.Read (readMaybe)

import           Config
import           Config.Macro
import           Config.Schema
import           Data.IP (IPRange)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import           Data.Word (Word16)
import           Network.Wai.Handler.Warp (HostPreference)
import qualified Text.PrettyPrint as Pretty

import           Control.Monad (unless)
import           Data.Bifunctor (first)
import qualified Data.Set as S
import           Network.DNS.Pattern (parsePattern)
import           Network.DNS.Pattern.Internal (DomainPattern(..),
                                               LabelPattern(..))
import           PowerDNS.API.Zones
import           PowerDNS.Gerd.Permission.Types (DomTyPat, Filtered(..),
                                                 Perms(..), RecTyPat(..),
                                                 SimplePerm(..), SrvPerm(..),
                                                 SrvPerm', WithDoc(WithDoc),
                                                 ZonePerm(..), ZonePerm',
                                                 describe)
import           PowerDNS.Gerd.User
import           UnliftIO (MonadIO, liftIO, throwIO)


data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey     :: T.Text
  , cfgUpstreamApiKeyType :: ApiKeyType
  , cfgListenAddress      :: HostPreference
  , cfgListenPort         :: Word16
  , cfgDefaultPerms       :: Perms
  , cfgUsers              :: [(Username, User)]
  , cfgTrustedProxies     :: [IPRange]
  }

data ApiKeyType = Key | Path

atomOrTextSpec :: T.Text -> ValueSpec ()
atomOrTextSpec l = atomOrTextSpec l <!> exactSpec (Text () l)

optSectionDefault' :: a -> T.Text -> ValueSpec a -> T.Text -> SectionsSpec a
optSectionDefault' def sect spec descr = fromMaybe def <$> optSection' sect spec descr

primAuthSpec :: T.Text -> ValueSpec [SimplePerm]
primAuthSpec ppName = [SimplePerm {..} ] <$ atomOrTextSpec "permit"

srvAuthSpec :: T.Text -> ValueSpec [SrvPerm']
srvAuthSpec spName = (pure <$> permit) <!> oneOrList
    (sectionsSpec "server-authorization-spec" $ do
      spServer <- reqSection' "server" textSpec "Matching this server. Defaults to localhost"
      spToken <- pure ()
      pure SrvPerm{..})
  where
    permit = atomOrTextSpec "permit" $>
            SrvPerm { spServer = "localhost"
                    , spToken = ()
                    , .. }

anyDomPat :: DomainPattern
anyDomPat = DomainPattern [DomGlobStar]

permZoneListSpec :: T.Text -> ValueSpec [SrvPerm Filtered]
permZoneListSpec spName = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-list-spec" $ do
        spServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        spToken <- reqSection' "type" filteredSpec "Whether or not records will be filtered using zoneUpdateRecords permissions"
        pure SrvPerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             SrvPerm { spServer = "localhost"
                     , spToken = Unfiltered
                     , .. }
    filtered = atomOrTextSpec "filtered" $>
            SrvPerm { spServer = "localhost"
                    , spToken = Filtered
                    , .. }

permZoneNotifySlavesSpec :: T.Text -> ValueSpec [ZonePerm Filtered]
permZoneNotifySlavesSpec zpName = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-notify-slaves-spec" $ do
        zpServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        zpPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        zpToken <- reqSection' "type" filteredSpec "If filtered, an API user may request a DNS NOTIFY when they have update access to any record."
        pure ZonePerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             ZonePerm { zpServer = "localhost"
                      , zpPattern = anyDomPat
                      , zpToken = Unfiltered
                      , .. }
    filtered = atomOrTextSpec "filtered" $>
               ZonePerm { zpServer = "localhost"
                        , zpPattern = anyDomPat
                        , zpToken = Filtered
                        , .. }

permZoneRectifySpec :: T.Text -> ValueSpec [ZonePerm Filtered]
permZoneRectifySpec zpName = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-rectify-spec" $ do
        zpServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        zpPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        zpToken <- reqSection' "type" filteredSpec "If filtered, an API user may rectify the zone when they have update access to any record."
        pure ZonePerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             ZonePerm { zpServer = "localhost"
                      , zpPattern = anyDomPat
                      , zpToken = Unfiltered
                      , .. }
    filtered = atomOrTextSpec "filtered" $>
               ZonePerm { zpServer = "localhost"
                        , zpPattern = anyDomPat
                        , zpToken = Filtered
                        , .. }

permZoneViewSpec :: T.Text -> ValueSpec [ZonePerm Filtered]
permZoneViewSpec zpName = (pure <$> permit) <!> (pure <$> filtered) <!> oneOrList
    (sectionsSpec "perm-zone-view-spec" $ do
        zpServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        zpPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        zpToken <- reqSection' "type" filteredSpec "Whether or not records in all zones will be filtered using zoneUpdateRecords permissions. If a zone has no visible records, it will be omitted entirely"
        pure ZonePerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             ZonePerm { zpServer = "localhost"
                      , zpPattern = anyDomPat
                      , zpToken = Unfiltered
                      , .. }
    filtered = atomOrTextSpec "filtered" $>
               ZonePerm { zpServer = "localhost"
                        , zpPattern = anyDomPat
                        , zpToken = Filtered
                        , .. }

permZoneSpec :: T.Text -> ValueSpec [ZonePerm']
permZoneSpec zpName = (pure <$> permit) <!> oneOrList
    (sectionsSpec "perm-zone-spec" $ do
        zpServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        zpPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        zpToken <- pure ()
        pure ZonePerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             ZonePerm { zpServer = "localhost"
                      , zpPattern = anyDomPat
                      , zpToken = ()
                      , .. }

domTyPatSpec :: SectionsSpec DomTyPat
domTyPatSpec = do
  domPat <- reqSection' "domain" domPatSpec "Matching any of these domains"
  recTyPat <- reqSection' "types" recTyPatSpec "Matching any of these record types"
  pure (domPat, recTyPat)

permZoneUpdateRecordsSpec :: T.Text -> ValueSpec [ZonePerm DomTyPat]
permZoneUpdateRecordsSpec zpName = (pure <$> permit) <!> oneOrList
    (sectionsSpec "perm-zone-update-records-spec" $ do
        zpServer <- optSectionDefault' "localhost" "server" textSpec "Matching this server. Defaults to localhost"
        zpPattern <- optSectionDefault' anyDomPat "zone" domPatSpec "Matching this zone. If left empty, will match any zone"
        zpToken <- domTyPatSpec
        pure ZonePerm{..})
  where
    permit = atomOrTextSpec "permit" $>
             ZonePerm { zpServer = "localhost"
                      , zpPattern = anyDomPat
                      , zpToken = (anyDomPat, AnyRecordType)
                      , .. }

permsSpec :: ValueSpec Perms
permsSpec = sectionsSpec "perms-spec" $ do
    permApiVersions       <- WithDoc <$> optSection2' "apiVersions" primAuthSpec (annotationFor permApiVersions)
    permServerList        <- WithDoc <$> optSection2' "serverList" primAuthSpec (annotationFor permServerList)
    permServerView        <- WithDoc <$> optSection2' "serverView" srvAuthSpec (annotationFor permServerView)
    permSearch            <- WithDoc <$> optSection2' "search" srvAuthSpec (annotationFor permSearch)
    permFlushCache        <- WithDoc <$> optSection2' "flushCache" srvAuthSpec (annotationFor permFlushCache)
    permStatistics        <- WithDoc <$> optSection2' "statistics" srvAuthSpec (annotationFor permStatistics)
    permZoneCreate        <- WithDoc <$> optSection2' "zoneCreate" srvAuthSpec (annotationFor permZoneCreate)
    permZoneList          <- WithDoc <$> optSection2' "zoneList" permZoneListSpec (annotationFor permZoneList)
    permZoneView          <- WithDoc <$> optSection2' "zoneView" permZoneViewSpec (annotationFor permZoneView)
    permZoneUpdate        <- WithDoc <$> optSection2' "zoneUpdate" permZoneSpec (annotationFor permZoneUpdate)
    permZoneUpdateRecords <- WithDoc <$> optSection2' "zoneUpdateRecords" permZoneUpdateRecordsSpec (annotationFor permZoneUpdateRecords)
    permZoneDelete        <- WithDoc <$> optSection2' "zoneDelete" permZoneSpec (annotationFor permZoneDelete)
    permZoneTriggerAxfr   <- WithDoc <$> optSection2' "zoneTriggerAxfr" permZoneSpec (annotationFor permZoneTriggerAxfr)
    permZoneGetAxfr       <- WithDoc <$> optSection2' "zoneGetAxfr" permZoneSpec (annotationFor permZoneGetAxfr)
    permZoneNotifySlaves  <- WithDoc <$> optSection2' "zoneNotifySlaves" permZoneNotifySlavesSpec (annotationFor permZoneNotifySlaves)
    permZoneRectify       <- WithDoc <$> optSection2' "zoneRectify" permZoneRectifySpec (annotationFor permZoneRectify)
    permZoneMetadata      <- WithDoc <$> optSection2' "zoneMetadata" permZoneSpec (annotationFor permZoneMetadata)
    permZoneCryptokeys    <- WithDoc <$> optSection2' "zoneCryptokeys" permZoneSpec (annotationFor permZoneCryptokeys)
    permTSIGKeyList       <- WithDoc <$> optSection2' "tsigKeyList" srvAuthSpec (annotationFor permTSIGKeyList)
    permTSIGKeyCreate     <- WithDoc <$> optSection2' "tsigKeyCreate" srvAuthSpec (annotationFor permTSIGKeyCreate)
    permTSIGKeyView       <- WithDoc <$> optSection2' "tsigKeyView" srvAuthSpec (annotationFor permTSIGKeyView)
    permTSIGKeyUpdate     <- WithDoc <$> optSection2' "tsigKeyUpdate" srvAuthSpec (annotationFor permTSIGKeyUpdate)
    permTSIGKeyDelete     <- WithDoc <$> optSection2' "tsigKeyDelete" srvAuthSpec (annotationFor permTSIGKeyDelete)

    pure Perms{..}
  where
    -- Helper to ensure that the section name we are parsing is passed down into the builder function.
    -- This lets us attach the section name to each permission that generated it.
    optSection2' x f = optSection' x (f x)
    annotationFor sel = "Permission to " <> describe sel

filteredSpec :: ValueSpec Filtered
filteredSpec = Filtered <$ atomOrTextSpec "filtered"
           <!> Unfiltered <$ atomOrTextSpec "unfiltered"

recTyPatSpec :: ValueSpec RecTyPat
recTyPatSpec = namedSpec "record-type-spec" $
                 AnyRecordType <$ atomOrTextSpec "any"
             <!> AnyOf <$> oneOrList recordAtomSpec

domPatSpec :: ValueSpec DomainPattern
domPatSpec = customSpec "Absolute domain (with trailing dot). A trailing globstar \"**\" or a wildcard \"*\" in place of a label can be specified."
                            textSpec
                            (first T.pack . parsePattern)

recordAtomSpec :: ValueSpec RecordType
recordAtomSpec =    A          <$ atomOrTextSpec "A"
                <!> AAAA       <$ atomOrTextSpec "AAAA"
                <!> AFSDB      <$ atomOrTextSpec "AFSDB"
                <!> ALIAS      <$ atomOrTextSpec "ALIAS"
                <!> APL        <$ atomOrTextSpec "APL"
                <!> CAA        <$ atomOrTextSpec "CAA"
                <!> CERT       <$ atomOrTextSpec "CERT"
                <!> CDNSKEY    <$ atomOrTextSpec "CDNSKEY"
                <!> CDS        <$ atomOrTextSpec "CDS"
                <!> CNAME      <$ atomOrTextSpec "CNAME"
                <!> DNSKEY     <$ atomOrTextSpec "DNSKEY"
                <!> DNAME      <$ atomOrTextSpec "DNAME"
                <!> DS         <$ atomOrTextSpec "DS"
                <!> HINFO      <$ atomOrTextSpec "HINFO"
                <!> KEY        <$ atomOrTextSpec "KEY"
                <!> LOC        <$ atomOrTextSpec "LOC"
                <!> MX         <$ atomOrTextSpec "MX"
                <!> NAPTR      <$ atomOrTextSpec "NAPTR"
                <!> NS         <$ atomOrTextSpec "NS"
                <!> NSEC       <$ atomOrTextSpec "NSEC"
                <!> NSEC3      <$ atomOrTextSpec "NSEC3"
                <!> NSEC3PARAM <$ atomOrTextSpec "NSEC3PARAM"
                <!> OPENPGPKEY <$ atomOrTextSpec "OPENPGPKEY"
                <!> PTR        <$ atomOrTextSpec "PTR"
                <!> RP         <$ atomOrTextSpec "RP"
                <!> RRSIG      <$ atomOrTextSpec "RRSIG"
                <!> SOA        <$ atomOrTextSpec "SOA"
                <!> SPF        <$ atomOrTextSpec "SPF"
                <!> SSHFP      <$ atomOrTextSpec "SSHFP"
                <!> SRV        <$ atomOrTextSpec "SRV"
                <!> TKEY       <$ atomOrTextSpec "TKEY"
                <!> TSIG       <$ atomOrTextSpec "TSIG"
                <!> TLSA       <$ atomOrTextSpec "TLSA"
                <!> SMIMEA     <$ atomOrTextSpec "SMIMEA"
                <!> TXT        <$ atomOrTextSpec "TXT"
                <!> URI        <$ atomOrTextSpec "URI"
                <!> A6         <$ atomOrTextSpec "A6"
                <!> DHCID      <$ atomOrTextSpec "DHCID"
                <!> DLV        <$ atomOrTextSpec "DLV"
                <!> EUI48      <$ atomOrTextSpec "EUI48"
                <!> EUI64      <$ atomOrTextSpec "EUI64"
                <!> IPSECKEY   <$ atomOrTextSpec "IPSECKEY"
                <!> KX         <$ atomOrTextSpec "KX"
                <!> MAILA      <$ atomOrTextSpec "MAILA"
                <!> MAILB      <$ atomOrTextSpec "MAILB"
                <!> MINFO      <$ atomOrTextSpec "MINFO"
                <!> MR         <$ atomOrTextSpec "MR"
                <!> RKEY       <$ atomOrTextSpec "RKEY"
                <!> SIG        <$ atomOrTextSpec "SIG"
                <!> WKS        <$ atomOrTextSpec "WKS"

hostPrefSpec :: ValueSpec HostPreference
hostPrefSpec = fromString . T.unpack <$> textSpec


configSpec :: ValueSpec Config
configSpec = sectionsSpec "top-level" $ do
  cfgUpstreamApiBaseUrl <- reqSection "upstreamApiBaseUrl" "The base URL of the upstream PowerDNS API."
  cfgUpstreamApiKey <- reqSection "upstreamApiKey" "The upstream X-API-Key secret or a path containing that secret."
  cfgUpstreamApiKeyType <- optSectionDefault' Key "upstreamApiKeyType"
                                                 ((Key <$ atomOrTextSpec "key") <!> (Path <$ atomOrTextSpec "path"))
                                                 "Path to a file containing the upstream X-API-Key secret."

  cfgListenAddress <- reqSection' "listenAddress" hostPrefSpec "The IP address the proxy will bind on"
  cfgListenPort <- reqSection "listenPort" "The TCP port the proxy will bind on"
  cfgUsers <- reqSection' "users" (listSpec userSpec) "API users"
  cfgDefaultPerms <- optSectionDefault' allForbidden "defaultPermissions" permsSpec "Default permissions. If a specific permission is not set under a user, If unset, all endpoints except API listing are forbidden by default."
  cfgTrustedProxies <- optSectionDefault' [] "trustedProxies" (listSpec iprSpec) "List of networks or IP addresses in which HTTP proxies reside, whose X-Forwarded-Host can be trusted. If a user has allowedFrom configured, and the server is behind a HTTP proxy, you must both configure the proxy to insert a X-Forwarded-For header and list its outbound IP address (or a network matching it) here."

  pure Config{..}

allForbidden :: Perms
allForbidden = Perms
  { permApiVersions       = WithDoc (Just [SimplePerm "apiVersions"])
  , permServerList        = WithDoc Nothing
  , permServerView        = WithDoc Nothing
  , permSearch            = WithDoc Nothing
  , permFlushCache        = WithDoc Nothing
  , permStatistics        = WithDoc Nothing
  , permZoneCreate        = WithDoc Nothing
  , permZoneList          = WithDoc Nothing
  , permZoneView          = WithDoc Nothing
  , permZoneUpdate        = WithDoc Nothing
  , permZoneUpdateRecords = WithDoc Nothing
  , permZoneDelete        = WithDoc Nothing
  , permZoneTriggerAxfr   = WithDoc Nothing
  , permZoneGetAxfr       = WithDoc Nothing
  , permZoneNotifySlaves  = WithDoc Nothing
  , permZoneRectify       = WithDoc Nothing
  , permZoneMetadata      = WithDoc Nothing
  , permZoneCryptokeys    = WithDoc Nothing
  , permTSIGKeyList       = WithDoc Nothing
  , permTSIGKeyCreate     = WithDoc Nothing
  , permTSIGKeyView       = WithDoc Nothing
  , permTSIGKeyUpdate     = WithDoc Nothing
  , permTSIGKeyDelete     = WithDoc Nothing
  }

pskSpec :: ValueSpec Credential
pskSpec = sectionsSpec "psk-spec" (CredPSK . T.encodeUtf8 <$> reqSection "psk" "Pre-shared key")

hashSpec :: ValueSpec Credential
hashSpec = sectionsSpec "hash-spec" (CredHash . T.encodeUtf8 <$> reqSection "hash" "Argon2id hash of the secret as a string in the original reference format, e.g.: \"$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG\".")

userSpec :: ValueSpec (Username, User)
userSpec = sectionsSpec "user-spec" $ do
  uName <- Username <$> reqSection "name" "The name of the API user"
  uCredential <- reqSection' "credential" (pskSpec <!> hashSpec) "Credential for this user"

  uPerms <- reqSection' "permissions" permsSpec "Permissions for this user"
  uAllowedFrom <- optSectionDefault' Nothing "allowedFrom" (Just <$> listSpec iprSpec) "List of IP addresses or networks the user is allowed to access the API from"

  pure (uName, User{..})

iprSpec :: ValueSpec IPRange
iprSpec = customSpec "IP Adress or range" textSpec go
  where
    go x = case readMaybe (T.unpack x) of
      Nothing  -> Left "failed to parse IP address or range"
      Just ipr -> Right ipr

loadValueFromFileWithMacros :: ValueSpec a -> FilePath -> IO a
loadValueFromFileWithMacros spec path =
  do txt <- T.readFile path
     let exceptIO m = either throwIO return m
     val <- exceptIO (parse txt)
     val' <- exceptIO (expandMacros val)
     exceptIO (loadValue spec val')

loadConfig :: MonadIO m => FilePath -> m Config
loadConfig path = liftIO $ do
  cfg <- loadValueFromFileWithMacros configSpec path
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
