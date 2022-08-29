-- |
-- Module: PowerDNS.Gerd.Permission.Types
-- Description: Definition for permission types
--
-- This module defines types and some utilities for permissions.
--
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}
module PowerDNS.Gerd.Permission.Types
  ( ZoneId(..)
  , Perms(..)
  , SrvPerm(..)
  , SrvPerm'
  , PrimPerm(..)
  , ZonePerm(..)
  , ZonePerm'
  , describe
  , WithDoc(..)
  , Perm(..)

  -- * Pattern types
  , DomTyPat
  , RecTyPat(..)

  -- * Utilities
  , Filtered(..)
  )
where

import           Data.Kind (Type)
import           Data.Proxy (Proxy(..))
import qualified Data.Text as T
import           GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import           Network.DNS (Domain)
import           Network.DNS.Pattern (DomainPattern, pprPattern)
import           PowerDNS.API (RecordType)

import           PowerDNS.Gerd.Utils (quoted, showT)

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
  { permApiVersions       :: Maybe [PrimPerm]
                            `WithDoc` "list api versions"

  -- Server wide
  , permServerList        :: Maybe [PrimPerm]
                             `WithDoc` "list servers"

  , permServerView        :: Maybe [SrvPerm']
                             `WithDoc` "view a server"

  , permSearch            :: Maybe [SrvPerm']
                             `WithDoc` "search"

  , permFlushCache        :: Maybe [SrvPerm']
                             `WithDoc` "flush cache"

  , permStatistics        :: Maybe [SrvPerm']
                             `WithDoc` "statistics"

  -- Zone wide
  , permZoneCreate        :: Maybe [SrvPerm']
                             `WithDoc` "create a zone"

  , permZoneList          :: Maybe [SrvPerm Filtered]
                             `WithDoc` "list zones"

  -- Per zone
  , permZoneView          :: Maybe [ZonePerm Filtered]
                             `WithDoc` "view a zone"

  , permZoneUpdate        :: Maybe [ZonePerm']
                             `WithDoc` "update a zone"

  , permZoneUpdateRecords :: Maybe [ZonePerm DomTyPat]
                             `WithDoc` "update a zones records"

  , permZoneDelete        :: Maybe [ZonePerm']
                             `WithDoc` "delete a zone"

  , permZoneTriggerAxfr   :: Maybe [ZonePerm']
                             `WithDoc` "trigger a zone axfr"

  , permZoneGetAxfr       :: Maybe [ZonePerm']
                             `WithDoc` "get a zone in axfr format"

  , permZoneNotifySlaves  :: Maybe [ZonePerm']
                             `WithDoc` "notify slaves"

  , permZoneRectify       :: Maybe [ZonePerm']
                             `WithDoc` "rectify a zone"

  , permZoneMetadata      :: Maybe [ZonePerm']
                             `WithDoc` "manipulate a zones metadata"

  , permZoneCryptokeys    :: Maybe [ZonePerm']
                             `WithDoc` "manipulate a zones cryptokeys"

  -- TSIG specific
  , permTSIGKeyList       :: Maybe [SrvPerm']
                             `WithDoc` "list tsig keys"

  , permTSIGKeyCreate     :: Maybe [SrvPerm']
                             `WithDoc` "create a tsig key"

  , permTSIGKeyView       :: Maybe [SrvPerm']
                             `WithDoc` "view a tsig key"

  , permTSIGKeyUpdate     :: Maybe [SrvPerm']
                             `WithDoc` "update a tsig key"

  , permTSIGKeyDelete     :: Maybe [SrvPerm']
                             `WithDoc` "delete a tsig key"
  }

-- | A primitive permission that unconditionally allows something. No patterns or tokens.
data PrimPerm = PrimPerm { ppName :: T.Text }
  deriving (Eq, Ord)

type ZonePerm' = ZonePerm ()
-- | A permission when matching a given zone and server. Provides a token when matched.
data ZonePerm tok = ZonePerm { zpServer :: T.Text
                             , zpPattern :: DomainPattern
                             , zpToken :: tok
                             , zpName :: T.Text }

type SrvPerm' = SrvPerm ()
-- | A permission when matching a given server. Provides a token when matched.
data SrvPerm tok = SrvPerm { spServer :: T.Text
                           , spToken :: tok
                           , spName :: T.Text }

class Perm p where
  type Tok p :: Type
  displayPerm :: p -> T.Text
  token :: p -> Tok p

(<+>) :: T.Text -> T.Text -> T.Text
l <+> r = l <> " " <> r

instance Show tok => Perm (ZonePerm tok) where
  type Tok (ZonePerm tok) = tok
  displayPerm p = "permission=" <> quoted (zpName p)
              <+> "server=" <> quoted (zpServer p)
              <+> "zone=" <> quoted (pprPattern (zpPattern p))
              <+> "token=" <> showT (zpToken p)
  token = zpToken

instance Show tok => Perm (SrvPerm tok) where
  type Tok (SrvPerm tok) = tok
  displayPerm p = "permission=" <> quoted (spName p)
              <+> "server=" <> quoted (spServer p)
              <+> "token=" <> showT (spToken p)
  token = spToken

instance Perm PrimPerm where
  type Tok PrimPerm = ()
  displayPerm p = "permission=" <> ppName p
  token _ = ()
