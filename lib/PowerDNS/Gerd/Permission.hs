-- |
-- Module: PowerDNS.Gerd.Permission
-- Description: Permission enforcement functions
--
-- This module defines utilities to enforce permission tokens based on server, zone and domain patterns.
--
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Gerd.Permission
  ( module PowerDNS.Gerd.Permission.Types

  -- * Authorization filters
  , matchingSrv
  , matchingZone

  -- * Pattern matchers
  , matchesDomTyPat
  , matchesRecTyPat
  , rrsetMatchesDomTyPat

  -- * Other utilities
  , pprDomTyPat
  )
where


import           Data.Bifunctor (first)
import qualified Data.Text as T
import           Network.DNS.Pattern (Domain(..), DomainPattern, matchesPattern,
                                      parseAbsDomain, pprPattern)
import qualified PowerDNS.API as PDNS
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Utils

-- | Test whether the 'RecTyPat' matches the given 'RecordType'
matchesRecTyPat :: PDNS.RecordType -> RecTyPat -> Bool
matchesRecTyPat _ AnyRecordType = True
matchesRecTyPat rt (AnyOf xs)   = rt `elem` xs

matchesDomTyPat :: Domain -> PDNS.RecordType -> DomTyPat -> Bool
matchesDomTyPat wantedDom wantedTy (pat, ty) = (wantedDom `matchesPattern` pat)
                                            && matchesRecTyPat wantedTy ty

-- | Filter permissions matching the specified server name.
matchingSrv :: T.Text -> [Authorization tok pat] -> [Authorization tok pat]
matchingSrv wantedSrv perms
    = [ e| e@(Authorization srv _dom _res) <- perms
      , wantedSrv == srv
      ]

-- | Filter permissions matching the specified zone and server name.
matchingZone :: T.Text -> ZoneId -> [Authorization tok DomainPattern] -> [Authorization tok DomainPattern]
matchingZone wantedSrv (ZoneId wantedZone) perms
    = [ e | e@(Authorization srv dom _tok) <- perms
      , wantedSrv == srv
      , wantedZone `matchesPattern` dom
      ]

-- | Test whether a given RRSet matches any of the specified 'DomTyPat' patterns.
rrsetMatchesDomTyPat :: [DomTyPat] -> PDNS.RRSet -> Either T.Text Bool
rrsetMatchesDomTyPat pats rrset = do
  let nam = PDNS.original (PDNS.rrset_name rrset)
      ty = PDNS.rrset_type rrset

  dom <- first (const ("failed to parse rrset: " <> nam))
                     (parseAbsDomain nam)

  pure (any (\(domPat, recTyPat) -> dom `matchesPattern` domPat
                                 && ty `matchesRecTyPat` recTyPat
            ) pats)


pprDomTyPat :: DomTyPat -> T.Text
pprDomTyPat (dom, ty) = pprPattern dom <> " " <> pprRecTyPat ty

pprRecTyPat :: RecTyPat -> T.Text
pprRecTyPat AnyRecordType = "(any)"
pprRecTyPat (AnyOf xs)    = "(" <> T.intercalate ", " (showT <$> xs) <> ")"
