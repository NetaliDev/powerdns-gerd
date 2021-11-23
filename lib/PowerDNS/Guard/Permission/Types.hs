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
  , DomainPermission(..)
  , PermissionList
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

type PermissionList (k :: DomainKind) = [(DomainSpec k, DomainPermission)]

data DomainPermission = MayModifyRecordType [RecordType]
                      | MayModifyAnyRecordType
                      deriving (Eq, Ord, Show)
