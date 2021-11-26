{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Gerd.Permission
  ( module PowerDNS.Gerd.Permission.Types
  , zoneViewPerm
  , elaborateDomainPerms
  , filterDomainPerms
  , getZonePermission
  )
where

import qualified Data.Map as M

import           Control.Monad (join)
import qualified Data.Text as T
import           PowerDNS.API (RecordType)
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

getZonePermission :: (ZonePermissions -> Authorization) -> T.Text -> User -> Authorization
getZonePermission f zone user = maybe Forbidden f (M.lookup (ZoneId zone) (_uZonePerms user))

zoneViewPerm :: User -> ZoneId -> Maybe ViewPermission
zoneViewPerm user zone = join (zpViewZone <$> M.lookup zone (_uZonePerms user))

elaborateDomainPerms :: User -> [ElabDomainPerm]
elaborateDomainPerms user = permsWithoutZoneId <> permsWithZoneId
  where
    permsWithoutZoneId :: [ElabDomainPerm]
    permsWithoutZoneId = do
      (pat, allowed) <- _uRecordPerms user
      pure ElabDomainPerm{ epZone = Nothing
                               , epDomainPat = pat
                               , epAllowed = allowed
                               }

    permsWithZoneId :: [ElabDomainPerm]
    permsWithZoneId = do
      (zone, perms) <- M.toList (_uZonePerms user)
      (pat, allowed) <- zpDomainPerms perms
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
