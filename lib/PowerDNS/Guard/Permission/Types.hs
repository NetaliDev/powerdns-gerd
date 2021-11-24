{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Guard.Permission.Types
  ( ZoneId(..)
  , DomainKind(..)
  , Domain(..)
  , DomainSpec(..)
  , RecordTypeSpec(..)
  , AllowSpec(..)
  , PermissionList
  , ElaboratedPermission(..)
  , ViewPermission(..)
  , ZonePermissions(..)
  , Authorization(..)
  )
where

import PowerDNS.API (RecordType)
import qualified Data.Text as T

data DomainKind = Absolute | Relative
newtype Domain (k :: DomainKind) = Domain { getDomain :: T.Text } deriving Show

instance Eq (Domain k) where
  Domain x == Domain y = T.toLower x == T.toLower y

newtype ZoneId = ZoneId { getZone :: T.Text } deriving (Eq, Ord, Show)

data DomainSpec (k :: DomainKind)
  = AnyDomain
  | ExactDomain (Domain k)
  | HasSuffix (Domain k)
  deriving Show

data RecordTypeSpec
  = AnyRecordType
  | AnyOf [RecordType]
  deriving Show

data ViewPermission = Filtered | Unfiltered
  deriving Show

data ZonePermissions = ZonePermissions
  { zoneDomainPermissions :: PermissionList
  , zoneViewPermission :: Maybe ViewPermission
  } deriving Show

type PermissionList = [(DomainSpec Absolute, AllowSpec)]

data Authorization = Forbidden | Authorized

-- | A domain permission that might be constrained to a particular zone
data ElaboratedPermission = ElaboratedPermission
  { epZone :: Maybe ZoneId
  , epDomain :: DomainSpec Absolute
  , epAllowed :: AllowSpec
  } deriving Show

data AllowSpec = MayModifyRecordType [RecordType]
               | MayModifyAnyRecordType
               deriving (Eq, Ord, Show)
