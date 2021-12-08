{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeFamilyDependencies #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , DomainKind(..)
  , Domain(..)
  , PermsF(..)
  , Perms
  , DescrPerms
  , Mode(..)
  , Inner
  , Authorization(..)
  , Authorization'
  , Authorization''
  , SimpleAuthorization(..)
  , permsDescr
  , Tagged(..)

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

data Mode = Field | Descr
type family Inner tag field = r | r -> tag field where
  Inner Field f = Maybe f
  Inner Descr f = Tagged f T.Text

data Tagged t a = Tagged { runTagged :: a }

type Perms = PermsF Field
type DescrPerms = PermsF Descr

deriving instance Eq Perms
deriving instance Ord Perms
deriving instance Show Perms

data PermsF f = PermsF
  { permApiVersions       :: Inner f [SimpleAuthorization]

  -- Server wide
  , permServerList        :: Inner f [Authorization'']
  , permServerView        :: Inner f [Authorization'']
  , permSearch            :: Inner f [Authorization'']
  , permFlushCache        :: Inner f [Authorization'']
  , permStatistics        :: Inner f [Authorization'']

  -- Zone wide
  , permZoneCreate        :: Inner f [Authorization'']
  , permZoneList          :: Inner f [Authorization Filtered ()]


  -- Per zone
  , permZoneView          :: Inner f [Authorization Filtered DomPat]
  , permZoneUpdate        :: Inner f [Authorization' DomPat]
  , permZoneUpdateRecords :: Inner f [Authorization DomTyPat DomPat]
  , permZoneDelete        :: Inner f [Authorization' DomPat]
  , permZoneTriggerAxfr   :: Inner f [Authorization' DomPat]
  , permZoneGetAxfr       :: Inner f [Authorization' DomPat]
  , permZoneNotifySlaves  :: Inner f [Authorization' DomPat]
  , permZoneRectify       :: Inner f [Authorization' DomPat]
  , permZoneMetadata      :: Inner f [Authorization' DomPat]
  , permZoneCryptokeys    :: Inner f [Authorization' DomPat]

  -- TSIG specific
  , permTSIGKeyList       :: Inner f [Authorization'']
  , permTSIGKeyCreate     :: Inner f [Authorization'']
  , permTSIGKeyView       :: Inner f [Authorization'']
  , permTSIGKeyUpdate     :: Inner f [Authorization'']
  , permTSIGKeyDelete     :: Inner f [Authorization'']
  }

permsDescr :: DescrPerms
permsDescr = PermsF
  { permApiVersions       = Tagged "listing API versions"
  , permServerList        = Tagged "listing servers"
  , permServerView        = Tagged "viewing servers"
  , permSearch            = Tagged "searching"
  , permFlushCache        = Tagged "flushing the cache"
  , permStatistics        = Tagged "getting statistics"
  , permZoneCreate        = Tagged "creating a zone"
  , permZoneList          = Tagged "listing a zone"
  , permZoneView          = Tagged "viewing a zone"
  , permZoneUpdate        = Tagged "updating a zone"
  , permZoneUpdateRecords = Tagged "updating records in a zone"
  , permZoneDelete        = Tagged "deleting a zone"
  , permZoneTriggerAxfr   = Tagged "triggering an AXFR"
  , permZoneGetAxfr       = Tagged "getting an AXFR"
  , permZoneNotifySlaves  = Tagged "notifying slaves"
  , permZoneRectify       = Tagged "rectifying a zone"
  , permZoneMetadata      = Tagged "manipulating a zones metadata"
  , permZoneCryptokeys    = Tagged "manipulating a zones cryptokeys"
  , permTSIGKeyList       = Tagged "listing tsig keys"
  , permTSIGKeyCreate     = Tagged "creating a tsig key"
  , permTSIGKeyView       = Tagged "viewing a tsig key"
  , permTSIGKeyUpdate     = Tagged "updating a tsig key"
  , permTSIGKeyDelete     = Tagged "deleting a tsig key"
  }

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
