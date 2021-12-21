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
  )
where

import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T
import           PowerDNS.Gerd.Permission.Types

newtype Username = Username { getUsername :: T.Text }
  deriving (Eq, Ord, Show)

data User = User
  { uName :: Username
  , uPassHash :: B8.ByteString
  , uPerms :: Perms
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
