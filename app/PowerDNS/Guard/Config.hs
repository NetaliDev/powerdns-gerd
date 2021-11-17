{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
module PowerDNS.Guard.Config
  ( Config(..)
  , loadConfig
  , configHelp
  )
where

import Config.Schema
import qualified Data.Text as T
import PowerDNS.Guard.Account
import Data.Word (Word16)
import qualified Data.Text.Encoding as T
import System.IO (hPutStrLn, stderr)
import System.Exit (exitFailure)
import Control.Exception (SomeException, displayException)
import UnliftIO.Exception (catch)
import Network.Wai.Handler.Warp (HostPreference)
import Data.String (fromString)
import qualified Text.PrettyPrint as Pretty
import Data.Maybe (fromMaybe)

data Config = Config
  { cfgUpstreamApiBaseUrl :: T.Text
  , cfgUpstreamApiKey :: T.Text
  , cfgListenAddress :: HostPreference
  , cfgListenPort :: Word16
  , cfgAccounts :: [Account]
  }

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
  acName <- reqSection "name" "The name of the API account"
  acHash <- reqSection' "hash" (T.encodeUtf8 <$> textSpec)"Argon2id hash of the secret as a string in the original reference format, e.g.: $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
  acMayListZones <- fromMaybe False <$> optSection' "mayListZones" yesOrNoSpec "Whether or not the account may list all zones of the server"
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
