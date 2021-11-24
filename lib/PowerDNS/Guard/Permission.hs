{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds         #-}
module PowerDNS.Guard.Permission
  ( module PowerDNS.Guard.Permission.Types
  , matchesDomainSpec
  , zoneViewPerm
  , elaboratePermissions
  , filterDomainPerms
  )
where

import qualified Data.Text as T
import qualified Data.Map as M

import PowerDNS.Guard.Permission.Types
import PowerDNS.Guard.Account
import Control.Monad (join)
import PowerDNS.API (RecordType)

matchesDomainSpec :: Domain k -> DomainSpec k -> Bool
matchesDomainSpec _ AnyDomain = True
matchesDomainSpec l (ExactDomain r) = l == r
matchesDomainSpec (Domain l) (HasSuffix (Domain r))
  -- Ensure that "*.foo" will not match "foo' itself.
  = ("." <> T.toLower r) `T.isSuffixOf` T.toLower l

matchesAllowSpec :: RecordType -> AllowSpec -> Bool
matchesAllowSpec _ MayModifyAnyRecordType = True
matchesAllowSpec rt (MayModifyRecordType xs) = rt `elem` xs

zoneViewPerm :: Account -> ZoneId -> Maybe ViewPermission
zoneViewPerm acc zone = join (zoneViewPermission <$> M.lookup zone (_acZonePerms acc))

elaboratePermissions :: Account -> [ElaboratedPermission]
elaboratePermissions acc = permsWithoutZoneId <> permsWithZoneId
  where
    permsWithoutZoneId :: [ElaboratedPermission]
    permsWithoutZoneId = do
      (spec, allowed) <- _acRecordPerms acc
      pure ElaboratedPermission{ epZone = Nothing
                               , epDomain = spec
                               , epAllowed = allowed
                               }

    permsWithZoneId :: [ElaboratedPermission]
    permsWithZoneId = do
      (zone, perms) <- M.toList (_acZonePerms acc)
      (spec, allowed) <- zoneDomainPermissions perms
      pure ElaboratedPermission{ epZone = Just zone
                               , epDomain = spec
                               , epAllowed = allowed
                               }

matchesZone :: ZoneId -> Maybe ZoneId -> Bool
matchesZone _ Nothing = True
matchesZone l (Just r) = l == r

filterDomainPerms :: ZoneId -> Domain Absolute -> RecordType -> [ElaboratedPermission] -> [ElaboratedPermission]
filterDomainPerms wantedZone wantedDomain wantedRecTy eperms
    = [ e| e@(ElaboratedPermission zone domain allow) <- eperms
      , matchesZone wantedZone zone
      , matchesDomainSpec wantedDomain domain
      , matchesAllowSpec wantedRecTy allow
      ]
