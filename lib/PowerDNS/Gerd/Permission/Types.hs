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
  , Perms(..)
  , Authorization(..)
  , Authorization'
  , Authorization''
  , SimpleAuthorization(..)

  -- * Pattern types
  , DomLabelPat(..)
  , DomTyPat
  , DomPat(..)
  , RecTyPat(..)

  -- * Utilities
  , DomainLabels(..)
  , Filtered(..)
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
  { getZone :: DomainLabels
  } deriving (Eq, Ord, Show)

newtype DomainLabels = DomainLabels
  { getDomainLabels :: [T.Text]
  } deriving (Eq, Ord, Show)

newtype DomPat = DomPat
  { getDomainPattern :: [DomLabelPat]
  } deriving (Eq, Ord, Show)

data DomLabelPat
  = DomLiteral T.Text
  | DomGlob -- ^ Represents a single asterisk glob matching any arbitrary domain at a given level.
  | DomGlobStar -- ^ Represents a double asterisk matching any arbitrary subdomain at a given level.
  deriving (Eq, Ord, Show)

data RecTyPat
  = AnyRecordType
  | AnyOf [RecordType]
  deriving (Eq, Ord, Show)

type DomTyPat = (DomPat, RecTyPat)

data Filtered = Filtered | Unfiltered
  deriving (Eq, Ord, Show)

data Perms = Perms
  { permApiVersions       :: [SimpleAuthorization]
  , permServerList        :: [Authorization'']
  , permServerView        :: [Authorization'']
  , permSearch            :: [Authorization'']
  , permFlushCache        :: [Authorization'']
  , permStatistics        :: [Authorization'']
  , permZoneCreate        :: [Authorization'']
  , permZoneList          :: [Authorization Filtered DomPat]
  , permZoneView          :: [Authorization Filtered DomPat]
  , permZoneUpdate        :: [Authorization' DomPat]
  , permZoneUpdateRecords :: [Authorization DomTyPat DomPat]
  , permZoneDelete        :: [Authorization' DomPat]
  , permZoneTriggerAxfr   :: [Authorization' DomPat]
  , permZoneGetAxfr       :: [Authorization' DomPat]
  , permZoneNotifySlaves  :: [Authorization' DomPat]
  , permZoneRectify       :: [Authorization' DomPat]
  , permZoneMetadata      :: [Authorization' DomPat]
  , permZoneCryptokeys    :: [Authorization' DomPat]
  , permTSIGKeyList       :: [Authorization'']
  , permTSIGKeyCreate     :: [Authorization'']
  , permTSIGKeyView       :: [Authorization'']
  , permTSIGKeyUpdate     :: [Authorization'']
  , permTSIGKeyDelete     :: [Authorization'']
  } deriving (Eq, Ord, Show)

-- | A simple convenient token to show we are authorized to do this. No patterns or tokens.
data SimpleAuthorization = SimpleAuthorization
  deriving (Eq, Ord, Show)

type Authorization' = Authorization ()
type Authorization'' = Authorization () ()

-- | A type of authorization. The 'tok' type variable designates what kind of token
-- we get when authorized, and 'pat' designates some kind of pattern that must match
-- for the authorization to work.
data Authorization tok pat = Authorization
  { authServer  :: T.Text -- ^ Server must match
  , authPattern :: pat    -- ^ Specified pattern must match
  , authToken   :: tok    -- ^ When everything matched, provide this as context.
  } deriving (Eq, Ord, Show, Functor)
