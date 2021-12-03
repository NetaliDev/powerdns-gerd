{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , DomainKind(..)
  , Domain(..)
  , RecordTypeSpec(..)
  , AllowSpec(..)
  , PermissionList
  , ElabDomainPerm(..)
  , FilteredPermission(..)
  , ZonePermissions(..)
  , PermSet(..)
  , Lookup(..)
  , Authorization(..)
  , ElabZonePerm(..)
  , DomainLabelPattern(..)
  , DomainPattern(..)
  , DomainLabels(..)
  )
where

import qualified Data.Map as M
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

data FilteredPermission = Filtered | Unfiltered
  deriving Show

deriving instance Show (PermSet Lookup)
deriving instance Show (PermSet M.Map)
deriving instance (Show k, Show v) => Show (Lookup k v)

newtype Lookup k v = Lookup { runLookup :: [(k, v)] }

-- | Parameterized over a lookup type. Either this is `Lookup` or `Map`.
-- See 'UnvalidatedPermSet' and 'ValidatedPermSet'.
data PermSet (c :: * -> * -> *) = PermSet
  { psZonePerms :: c ZoneId ZonePermissions
  , psUnrestrictedDomainPerms :: PermissionList
  , psCreateZone :: Authorization ()
  , psListZones :: Authorization FilteredPermission
  }

data ZonePermissions = ZonePermissions
  { zpViewZone :: Authorization FilteredPermission
  , zpDomainPerms :: PermissionList
  , zpUpdateZone :: Authorization ()
  , zpDeleteZone :: Authorization ()
  , zpTriggerAxfr :: Authorization ()
  , zpNotifySlaves :: Authorization ()
  , zpGetZoneAxfr :: Authorization ()
  , zpRectifyZone :: Authorization ()
  } deriving Show

type PermissionList = [(DomainPattern, AllowSpec)]

data Authorization a = Forbidden | Authorized a
  deriving (Eq, Ord, Show, Functor)

data ElabZonePerm = ElabZonePerm
  { ezZone :: ZoneId
  , ezView :: Authorization FilteredPermission
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
