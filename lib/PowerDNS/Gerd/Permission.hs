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

  -- * Other utilities
  , domPatWorksInside
  , pprDomTyPat
  )
where


import           Data.Bifunctor (first)
import qualified Data.Text as T
import qualified PowerDNS.API as PDNS
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.Utils

domPatWorksInside :: DomPat -> DomainLabels -> Bool
domPatWorksInside (DomPat x) (DomainLabels y) = go (reverse x) (reverse y)
  where
    go :: [DomLabelPat] -> [T.Text] -> Bool
    go [DomGlobStar] _ = True
    go [] []           = True
    go [] _ls          = False
    go _p []           = True
    go (p:ps) (l:ls)   = patternMatches l p && go ps ls


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


pprDomTyPat :: DomTyPat -> T.Text
pprDomTyPat (dom, ty) = pprDomPat dom <> " " <> pprRecTyPat ty

pprRecTyPat :: RecTyPat -> T.Text
pprRecTyPat AnyRecordType = "(any)"
pprRecTyPat (AnyOf xs)    = "(" <> T.intercalate ", " (showT <$> xs) <> ")"

pprDomPat :: DomPat -> T.Text
pprDomPat (DomPat patterns) = mconcat (pprLabelPattern <$> patterns)

pprLabelPattern :: DomLabelPat -> T.Text
pprLabelPattern (DomLiteral t) = t <> "."
pprLabelPattern DomGlob        = "*."
pprLabelPattern DomGlobStar    = "**."

