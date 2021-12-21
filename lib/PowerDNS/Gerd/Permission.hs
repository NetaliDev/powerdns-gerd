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
  , matchesDomPat
  , matchesRecTyPat
  , rrsetMatchesDomTyPat
  )
where


import           Data.Bifunctor (first)
import qualified Data.Text as T
import qualified PowerDNS.API as PDNS
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Utils

matchesDomPat :: DomainLabels -> DomPat -> Bool
matchesDomPat (DomainLabels x) (DomPat y) = go (reverse x) (reverse y)
  where
    go :: [T.Text] -> [DomLabelPat] -> Bool
    go []   []            = True
    go []  _ps            = False
    go _ls  []            = False
    go _ls  [DomGlobStar] = True
    go (l:ls) (p:ps)      = patternMatches l p && go ls ps

    patternMatches :: T.Text -> DomLabelPat -> Bool
    patternMatches _l DomGlob       = True
    patternMatches l (DomLiteral p) = l == p
    patternMatches _l DomGlobStar   = error "patternMatches: impossible! DomGlobStar in the middle"

matchesRecTyPat :: PDNS.RecordType -> RecTyPat -> Bool
matchesRecTyPat _ AnyRecordType = True
matchesRecTyPat rt (AnyOf xs)   = rt `elem` xs

matchesDomTyPat :: DomainLabels -> PDNS.RecordType -> DomTyPat -> Bool
matchesDomTyPat wantedDom wantedTy (dom, ty) = matchesDomPat wantedDom dom
                                            && matchesRecTyPat wantedTy ty

matchingSrv :: T.Text -> [Authorization tok pat] -> [Authorization tok pat]
matchingSrv wantedSrv perms
    = [ e| e@(Authorization srv _dom _res) <- perms
      , wantedSrv == srv
      ]

matchingZone :: T.Text -> ZoneId -> [Authorization tok DomPat] -> [Authorization tok DomPat]
matchingZone wantedSrv (ZoneId wantedZone) perms
    = [ e | e@(Authorization srv dom _tok) <- perms
      , wantedSrv == srv
      , matchesDomPat wantedZone dom
      ]

-- | Test whether a given RRSet matches any of the specified 'DomTyPat' patterns.
rrsetMatchesDomTyPat :: [DomTyPat] -> PDNS.RRSet -> Either T.Text Bool
rrsetMatchesDomTyPat pats rrset = do
  let nam = PDNS.rrset_name rrset
      ty = PDNS.rrset_type rrset

  labels <- first (const ("failed to parse rrset: " <> nam))
                  (parseAbsDomainLabels nam)

  pure (any (\(domPat, recTyPat) -> labels `matchesDomPat` domPat
                                 && ty `matchesRecTyPat` recTyPat
            ) pats)
