{-# LANGUAGE DataKinds #-}
module PowerDNS.Guard.Account.Types
  ( Account(..)
  )
where

import PowerDNS.Guard.Permission.Types
import qualified Data.Map as M
import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T

data Account = Account
  { _acName :: T.Text
  , _acPassHash :: B8.ByteString
  , _acZonePerms :: M.Map ZoneId (PermissionList Relative)
  , _acRecordPerms :: PermissionList Absolute
  } deriving Show
