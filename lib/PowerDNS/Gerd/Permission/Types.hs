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
  , PerZonePerms(..)
  , PermSet(..)
  , Lookup(..)
  , Authorization(..)
  , ElabZonePerm(..)
  , DomainLabelPattern(..)
  , DomainPattern(..)
  , DomainLabels(..)
  , ServerPerms(..)
  , CryptokeyPerms(..)
  , TSIGKeyPerms(..)
  , MetadataPerms(..)
  , ZonePerms(..)
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
deriving instance Show (ZonePerms Lookup)
deriving instance Show (ZonePerms M.Map)
deriving instance (Show k, Show v) => Show (Lookup k v)

newtype Lookup k v = Lookup { runLookup :: [(k, v)] }

-- | Parameterized over a lookup type. Either this is `Lookup` or `Map`.
-- See 'UnvalidatedPermSet' and 'ValidatedPermSet'.
data PermSet (c :: * -> * -> *) = PermSet
  { psVersionsPerms :: Authorization ()
  , psServersPerms :: ServerPerms
  , psOurZonePerms :: ZonePerms c
  , psTSIGKeyPerms :: TSIGKeyPerms
  }

-- | Permissions pertaining to the @/servers@ endpoints
data ServerPerms = ServerPerms
  { spListServers :: Authorization ()
  , spGetServer :: Authorization ()
  , spSearch :: Authorization ()
  , spFlushCache :: Authorization ()
  , spStatistics :: Authorization ()
  } deriving Show

-- | Permissions pertaining to the @/zones@ endpoints
data ZonePerms (c :: * -> * -> *) = ZonePerms
  { zpUnrestrictedDomainPerms :: PermissionList
  , zpZones :: c ZoneId PerZonePerms
  , zpCreateZone :: Authorization ()
  , zpListZones :: Authorization FilteredPermission
  }

-- | Permissions pertaining to the @/zones/:zone_id@ endpoints
data PerZonePerms = PerZonePerms
  { pzpViewZone :: Authorization FilteredPermission
  , pzpDomainPerms :: PermissionList
  , pzpUpdateZone :: Authorization ()
  , pzpDeleteZone :: Authorization ()
  , pzpTriggerAxfr :: Authorization ()
  , pzpNotifySlaves :: Authorization ()
  , pzpGetZoneAxfr :: Authorization ()
  , pzpRectifyZone :: Authorization ()

  -- | Permissions pertaining to the @/zones/:zoneid/metadata@ endpoints
  , pzpMetadataPerms :: MetadataPerms
  -- | Permissions pertaining to the @/zones/:zoneid/cryptokeys@ endpoints
  , pzpCryptokeysPerms :: CryptokeyPerms
  } deriving Show

-- | Permissions pertaining to the @/zones/:zoneid/cryptokeys@ endpoints
data CryptokeyPerms = CryptokeyPerms
  { cpAny :: Authorization () -- ^ Whether or not any cryptokey operation is allowed or not.
  } deriving Show

-- | Permissions pertaining to the @/zones/:zoneid/metadata@ endpoints
data MetadataPerms = MetadataPerms
  { mdAny :: Authorization () -- ^ Whether or not any cryptokey operation is allowed or not.
  } deriving Show

-- | Permissions pertaining to the @/cryptokeys/@ endpoints
data TSIGKeyPerms = TSIGKeyPerms
  { tspAny :: Authorization () -- ^ Whether or not any TSIGKey operation is allowed or not.
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
