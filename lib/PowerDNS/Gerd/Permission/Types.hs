{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures    #-}
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , DomainKind(..)
  , Domain(..)
  , RecordTypeSpec(..)
  , AllowSpec(..)
  , PermissionList
  , ElabDomainPerm(..)
  , ViewPermission(..)
  , ZonePermissions(..)
  , Authorization(..)
  , ElabZonePerm(..)
  , DomainLabelPattern(..)
  , DomainPattern(..)
  , DomainLabels(..)
  )
where

import qualified Data.Text as T
import           PowerDNS.API (RecordType)

data DomainKind = Absolute | Relative

newtype Domain (k :: DomainKind) = Domain
  { getDomain :: T.Text
  } deriving Show

instance Eq (Domain k) where
  Domain x == Domain y = T.toLower x == T.toLower y

newtype ZoneId = ZoneId
  { getZone :: T.Text
  } deriving (Eq, Ord, Show)

newtype DomainLabels = DomainLabels
  { getDomainLabels :: [T.Text]
  }

newtype DomainPattern = DomainPattern
  { getDomainPattern :: [DomainLabelPattern]
  } deriving Show

data DomainLabelPattern
  = DomLiteral T.Text
  | DomGlob -- ^ Represents a single asterisk glob matching any arbitrary domain at a given level.
  | DomGlobStar -- ^ Represents a double asterisk matching any arbitrary subdomain at a given level.
  deriving Show

data RecordTypeSpec
  = AnyRecordType
  | AnyOf [RecordType]
  deriving Show

data ViewPermission = Filtered | Unfiltered
  deriving Show

data ZonePermissions = ZonePermissions
  { zpDomainPerms :: PermissionList
  , zpViewZone :: Maybe ViewPermission
  , zpUpdateZone :: Authorization
  , zpDeleteZone :: Authorization
  , zpTriggerAxfr :: Authorization
  , zpNotifySlaves :: Authorization
  , zpGetZoneAxfr :: Authorization
  , zpRectifyZone :: Authorization
  } deriving Show

type PermissionList = [(DomainPattern, AllowSpec)]

data Authorization = Forbidden | Authorized
  deriving Show

data ElabZonePerm = ElabZonePerm
  { ezZone :: ZoneId
  , ezView :: Maybe ViewPermission
  }

-- | A domain permission that might be constrained to a particular zone
data ElabDomainPerm = ElabDomainPerm
  { epZone :: Maybe ZoneId
  , epDomainPat :: DomainPattern
  , epAllowed :: AllowSpec
  } deriving Show

data AllowSpec = MayModifyRecordType [RecordType]
               | MayModifyAnyRecordType
               deriving (Eq, Ord, Show)
