-- |
-- Module: PowerDNS.Gerd.Permission.Types
-- Description: Definition for permission types
--
-- This module defines types and some utilities for permissions.
--
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators       #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , Perms(..)
  , Authorization(..)
  , Authorization'
  , Authorization''
  , SimpleAuthorization(..)
  , describe
  , WithDoc(..)

  -- * Pattern types
  , DomTyPat
  , RecTyPat(..)

  -- * Utilities
  , Filtered(..)
  )
where

import           Data.Proxy (Proxy(..))
import qualified Data.Text as T
import           GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import           Network.DNS.Pattern (Domain, DomainPattern)
import           PowerDNS.API (RecordType)

newtype ZoneId = ZoneId { getZone :: Domain }

data RecTyPat
  = AnyRecordType
  | AnyOf [RecordType]
  deriving (Eq, Ord, Show)

type DomTyPat = (DomainPattern, RecTyPat)

data Filtered = Filtered | Unfiltered
  deriving (Eq, Ord, Show)

newtype WithDoc b (s :: Symbol) = WithDoc { withoutDoc :: b }

-- | Demote the type level WithDoc symbol from a Perms Selector
describe :: forall s a. KnownSymbol s => (Perms -> WithDoc a s) -> T.Text
describe _ = T.pack (symbolVal (Proxy :: Proxy s))

data Perms = Perms
  { permApiVersions       :: Maybe [SimpleAuthorization]
                            `WithDoc` "list api versions"

  -- Server wide
  , permServerList        :: Maybe [SimpleAuthorization]
                             `WithDoc` "list servers"

  , permServerView        :: Maybe [Authorization'']
                             `WithDoc` "view a server"

  , permSearch            :: Maybe [Authorization'']
                             `WithDoc` "search"

  , permFlushCache        :: Maybe [Authorization'']
                             `WithDoc` "flush cache"

  , permStatistics        :: Maybe [Authorization'']
                             `WithDoc` "statistics"

  -- Zone wide
  , permZoneCreate        :: Maybe [Authorization'']
                             `WithDoc` "create a zone"

  , permZoneList          :: Maybe [Authorization Filtered ()]
                             `WithDoc` "list zones"

  -- Per zone
  , permZoneView          :: Maybe [Authorization Filtered DomainPattern]
                             `WithDoc` "view a zone"

  , permZoneUpdate        :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "update a zone"

  , permZoneUpdateRecords :: Maybe [Authorization DomTyPat DomainPattern]
                             `WithDoc` "update a zones records"

  , permZoneDelete        :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "delete a zone"

  , permZoneTriggerAxfr   :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "trigger a zone axfr"

  , permZoneGetAxfr       :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "get a zone in axfr format"

  , permZoneNotifySlaves  :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "notify slaves"

  , permZoneRectify       :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "rectify a zone"

  , permZoneMetadata      :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "manipulating a zones metadata"

  , permZoneCryptokeys    :: Maybe [Authorization' DomainPattern]
                             `WithDoc` "manipulating a zones cryptokeys"

  -- TSIG specific
  , permTSIGKeyList       :: Maybe [Authorization'']
                             `WithDoc` "list tsig keys"

  , permTSIGKeyCreate     :: Maybe [Authorization'']
                             `WithDoc` "create a tsig key"

  , permTSIGKeyView       :: Maybe [Authorization'']
                             `WithDoc` "view a tsig key"

  , permTSIGKeyUpdate     :: Maybe [Authorization'']
                             `WithDoc` "update a tsig key"

  , permTSIGKeyDelete     :: Maybe [Authorization'']
                             `WithDoc` "delete a tsig key"
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
  } deriving (Eq, Ord, Show)
