{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE PolyKinds #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , DomainKind(..)
  , Domain(..)
  , Perms(..)
  , Authorization(..)
  , Authorization'
  , Authorization''
  , SimpleAuthorization(..)
  , describe
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

import           Data.Proxy (Proxy(..))
import           GHC.TypeLits (KnownSymbol, symbolVal)
import qualified Data.Text as T
import           PowerDNS.API (RecordType)
import Servant.Server (Tagged(..))

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

-- | Demote the type level Tagged symbol from a Perms Selector
describe :: forall s a. KnownSymbol s => (Perms -> Tagged s a) -> T.Text
describe _ = T.pack (symbolVal (Proxy :: Proxy s))

data Perms = Perms
  { permApiVersions       :: Tagged "list api versions" (Maybe [SimpleAuthorization])

  -- Server wide
  , permServerList        :: Tagged "list servers"  (Maybe [Authorization''])
  , permServerView        :: Tagged "view a server" (Maybe [Authorization''])
  , permSearch            :: Tagged "search"       (Maybe [Authorization''])
  , permFlushCache        :: Tagged "flush cache"  (Maybe [Authorization''])
  , permStatistics        :: Tagged "statistics"   (Maybe [Authorization''])

  -- Zone wide
  , permZoneCreate        :: Tagged "create a zone" (Maybe [Authorization''])
  , permZoneList          :: Tagged "list zones"    (Maybe [Authorization Filtered ()])


  -- Per zone
  , permZoneView          :: Tagged "view a zone"   (Maybe [Authorization Filtered DomPat])
  , permZoneUpdate        :: Tagged "update a zone" (Maybe [Authorization' DomPat])
  , permZoneUpdateRecords :: Tagged "update a zones records" (Maybe [Authorization DomTyPat DomPat])
  , permZoneDelete        :: Tagged "delete a zone" (Maybe [Authorization' DomPat])
  , permZoneTriggerAxfr   :: Tagged "trigger a zone axfr" (Maybe [Authorization' DomPat])
  , permZoneGetAxfr       :: Tagged "get a zone in axfr format" (Maybe [Authorization' DomPat])
  , permZoneNotifySlaves  :: Tagged "notify slaves" (Maybe [Authorization' DomPat])
  , permZoneRectify       :: Tagged "rectify a zone" (Maybe [Authorization' DomPat])
  , permZoneMetadata      :: Tagged "manipulating a zones metadata" (Maybe [Authorization' DomPat])
  , permZoneCryptokeys    :: Tagged "manipulating a zones cryptokeys" (Maybe [Authorization' DomPat])

  -- TSIG specific
  , permTSIGKeyList       :: Tagged "list tsig keys" (Maybe [Authorization''])
  , permTSIGKeyCreate     :: Tagged "create a tsig key" (Maybe [Authorization''])
  , permTSIGKeyView       :: Tagged "view a tsig key" (Maybe [Authorization''])
  , permTSIGKeyUpdate     :: Tagged "update a tsig key" (Maybe [Authorization''])
  , permTSIGKeyDelete     :: Tagged "delete a tsig key" (Maybe [Authorization''])
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
