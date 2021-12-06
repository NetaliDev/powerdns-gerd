{-# LANGUAGE DataKinds #-}
module PowerDNS.Gerd.User.Types
  ( User(..)
  , Username(..)
  , UserNonValidated(..)
  , MemLimit(..)
  , OpsLimit(..)
  )
where

import qualified Data.ByteString.Char8 as B8
import qualified Data.Map as M
import qualified Data.Text as T
import           PowerDNS.Gerd.Permission.Types

newtype Username = Username { getUsername :: T.Text }
  deriving (Eq, Ord, Show)

data User = User
  { uName :: Username
  , uPassHash :: B8.ByteString
  , uPerms :: PermSet M.Map
  } deriving Show

data UserNonValidated = UserNonValidated
  { unvName :: Username
  , unvPassHash :: B8.ByteString
  , unvPerms :: PermSet Lookup
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
