-- |
-- Module: PowerDNS.Gerd.User.Types
-- Description: Definition for user types
--
-- This module defines types for API user types.
--
module PowerDNS.Gerd.User.Types
  ( User(..)
  , Username(..)
  , MemLimit(..)
  , OpsLimit(..)
  , Credential(..)
  )
where

import qualified Data.ByteString as BS
import           Data.IP
import qualified Data.Text as T
import           PowerDNS.Gerd.Permission.Types

newtype Username = Username { getUsername :: T.Text }
  deriving (Eq, Ord, Show)

data Credential = CredHash BS.ByteString
                | CredPSK BS.ByteString

data User = User
  { uName        :: Username
  , uCredential  :: Credential
  , uPerms       :: Perms
  , uAllowedFrom :: Maybe [IPRange]
  }

data MemLimit = MemMin
              | MemInteractive
              | MemModerate
              | MemSensitive
              | MemMax
              deriving (Eq, Ord, Show, Read)

data OpsLimit = OpsMin
              | OpsInteractive
              | OpsModerate
              | OpsSensitive
              | OpsMax
              deriving (Eq, Ord, Show, Read)
