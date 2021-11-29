{-# LANGUAGE DataKinds #-}
module PowerDNS.Gerd.User.Types
  ( User(..)
  , MemLimit(..)
  , OpsLimit(..)
  )
where

import qualified Data.ByteString.Char8 as B8
import qualified Data.Map as M
import qualified Data.Text as T
import           PowerDNS.Gerd.Permission.Types

data User = User
  { _uName :: T.Text
  , _uPassHash :: B8.ByteString
  , _uZonePerms :: M.Map ZoneId ZonePermissions
  , _uRecordPerms :: PermissionList
  } deriving Show

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
