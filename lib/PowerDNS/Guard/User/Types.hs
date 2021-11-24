{-# LANGUAGE DataKinds #-}
module PowerDNS.Guard.User.Types
  ( User(..)
  )
where

import PowerDNS.Guard.Permission.Types
import qualified Data.Map as M
import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T

data User = User
  { _uName :: T.Text
  , _uPassHash :: B8.ByteString
  , _uZonePerms :: M.Map ZoneId ZonePermissions
  , _uRecordPerms :: PermissionList
  } deriving Show
