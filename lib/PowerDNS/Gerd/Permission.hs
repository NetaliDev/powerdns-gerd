{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedLabels  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications  #-}
module PowerDNS.Gerd.Permission
  ( module PowerDNS.Gerd.Permission.Types
  , elaborateDomainPerms
  , filterDomainPerms
  , userPerZonePerms
  , getAuthorization
  )
where

import qualified Data.Map as M

import           Data.Maybe (fromMaybe)
import qualified Data.Text as T
import           Optics
import           PowerDNS.API (RecordType)
import           PowerDNS.Gerd.Permission.Optics ()
import           PowerDNS.Gerd.Permission.Types
import           PowerDNS.Gerd.User

matchesDomainPat :: DomainLabels -> DomainPattern -> Bool
matchesDomainPat (DomainLabels x) (DomainPattern y) = go (reverse x) (reverse y)
  where
    go :: [T.Text] -> [DomainLabelPattern] -> Bool
    go []   []            = True
    go []  _ps            = False
    go _ls  []            = False
    go _ls  [DomGlobStar] = True
    go (l:ls) (p:ps)      = patternMatches l p && go ls ps

    patternMatches :: T.Text -> DomainLabelPattern -> Bool
    patternMatches _l DomGlob       = True
    patternMatches l (DomLiteral p) = l == p
    patternMatches _l DomGlobStar   = error "patternMatches: impossible! DomGlobStar in the middle"

matchesAllowSpec :: RecordType -> AllowSpec -> Bool
matchesAllowSpec _ MayModifyAnyRecordType    = True
matchesAllowSpec rt (MayModifyRecordType xs) = rt `elem` xs

userPerZonePerms :: ZoneId -> Lens' PerZonePerms (Authorization a) -> AffineFold User (Authorization a)
userPerZonePerms zone f = castOptic $
  #uPerms % #psOurZonePerms % #zpZones % at zone % _Just % f

getAuthorization :: AffineFold User (Authorization a) -> User -> Authorization a
getAuthorization f u = fromMaybe Forbidden (preview f u)

elaborateDomainPerms :: User -> [ElabDomainPerm]
elaborateDomainPerms user = permsWithoutZoneId <> permsWithZoneId
  where
    permsWithoutZoneId :: [ElabDomainPerm]
    permsWithoutZoneId = do
      (pat, allowed) <- user ^. #uPerms % #psOurZonePerms % #zpUnrestrictedDomainPerms
      pure ElabDomainPerm{ epZone = Nothing
                         , epDomainPat = pat
                         , epAllowed = allowed
                         }

    permsWithZoneId :: [ElabDomainPerm]
    permsWithZoneId = do
      (zone, ps) <- user ^. #uPerms % #psOurZonePerms % #zpZones % to M.toList
      (pat, allowed) <- ps ^. #pzpDomainPerms
      pure ElabDomainPerm{ epZone = Just zone
                         , epDomainPat = pat
                         , epAllowed = allowed
                         }

matchesZone :: ZoneId -> Maybe ZoneId -> Bool
matchesZone _ Nothing  = True
matchesZone l (Just r) = l == r

filterDomainPerms :: ZoneId -> DomainLabels -> RecordType -> [ElabDomainPerm] -> [ElabDomainPerm]
filterDomainPerms wantedZone wantedDomain wantedRecTy eperms
    = [ e| e@(ElabDomainPerm zone pat allow) <- eperms
      , matchesZone wantedZone zone
      , matchesDomainPat wantedDomain pat
      , matchesAllowSpec wantedRecTy allow
      ]
