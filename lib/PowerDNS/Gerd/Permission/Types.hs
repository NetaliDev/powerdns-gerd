{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DeriveFunctor      #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE TypeOperators #-}
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
  , WithDocs(..)

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
import           GHC.TypeLits (KnownSymbol, symbolVal, Symbol)
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

newtype WithDocs b (s :: Symbol) = WithDocs { withoutDocs :: b }

-- | Demote the type level WithDocs symbol from a Perms Selector
describe :: forall s a. KnownSymbol s => (Perms -> WithDocs a s) -> T.Text
describe _ = T.pack (symbolVal (Proxy :: Proxy s))

data Perms = Perms
  { permApiVersions       :: Maybe [SimpleAuthorization] `WithDocs` "list api versions"

  -- Server wide
  , permServerList        :: Maybe [Authorization''] `WithDocs` "list servers"
  , permServerView        :: Maybe [Authorization''] `WithDocs` "view a server"
  , permSearch            :: Maybe [Authorization''] `WithDocs` "search"
  , permFlushCache        :: Maybe [Authorization''] `WithDocs` "flush cache"
  , permStatistics        :: Maybe [Authorization''] `WithDocs` "statistics"

  -- Zone wide
  , permZoneCreate        :: Maybe [Authorization''] `WithDocs` "create a zone"
  , permZoneList          :: Maybe [Authorization Filtered ()] `WithDocs` "list zones"


  -- Per zone
  , permZoneView          :: Maybe [Authorization Filtered DomPat] `WithDocs` "view a zone"
  , permZoneUpdate        :: Maybe [Authorization' DomPat] `WithDocs` "update a zone"
  , permZoneUpdateRecords :: Maybe [Authorization DomTyPat DomPat] `WithDocs` "update a zones records"
  , permZoneDelete        :: Maybe [Authorization' DomPat] `WithDocs` "delete a zone"
  , permZoneTriggerAxfr   :: Maybe [Authorization' DomPat] `WithDocs` "trigger a zone axfr"
  , permZoneGetAxfr       :: Maybe [Authorization' DomPat] `WithDocs` "get a zone in axfr format"
  , permZoneNotifySlaves  :: Maybe [Authorization' DomPat] `WithDocs` "notify slaves"
  , permZoneRectify       :: Maybe [Authorization' DomPat] `WithDocs` "rectify a zone"
  , permZoneMetadata      :: Maybe [Authorization' DomPat] `WithDocs` "manipulating a zones metadata"
  , permZoneCryptokeys    :: Maybe [Authorization' DomPat] `WithDocs` "manipulating a zones cryptokeys"

  -- TSIG specific
  , permTSIGKeyList       :: Maybe [Authorization''] `WithDocs` "list tsig keys"
  , permTSIGKeyCreate     :: Maybe [Authorization''] `WithDocs` "create a tsig key"
  , permTSIGKeyView       :: Maybe [Authorization''] `WithDocs` "view a tsig key"
  , permTSIGKeyUpdate     :: Maybe [Authorization''] `WithDocs` "update a tsig key"
  , permTSIGKeyDelete     :: Maybe [Authorization''] `WithDocs` "delete a tsig key"
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
