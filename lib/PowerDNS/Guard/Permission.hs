{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
module PowerDNS.Guard.Permission
  ( module PowerDNS.Guard.Permission.Types
  , matchesDomainSpec
  , domainPerms
  )
where

import qualified Data.Text as T
import qualified Data.Map as M

import PowerDNS.Guard.Permission.Types
import PowerDNS.Guard.Account
import Data.Maybe (fromMaybe)

matchesDomainSpec :: Domain k -> DomainSpec k -> Bool
matchesDomainSpec _ AnyDomain = True
matchesDomainSpec l (ExactDomain r) = l == r
matchesDomainSpec (Domain l) (HasSuffix (Domain r))
  -- Ensure that "*.foo" will not match "foo' itself.
  = ("." <> T.toLower r) `T.isSuffixOf` T.toLower l

domainPerms :: Account -> ZoneId -> Domain Absolute -> [DomainPermission]
domainPerms acc zone wanted = globalPerms <> zoneConstrainedPerms
  where
    relDomain :: Maybe (Domain Relative)
    relDomain = Domain <$> T.stripSuffix ("." <> getZone zone) (getDomain wanted)
    
    globalPerms :: [DomainPermission]
    globalPerms =
      (fmap snd . filter (matchesDomainSpec wanted . fst))
      (_acRecordPerms acc)
    
    zoneConstrainedPerms :: [DomainPermission]
    zoneConstrainedPerms = fromMaybe [] $ do
      rel <- relDomain
      zonePerms <- M.lookup zone (_acZonePerms acc)
      pure (fmap snd . filter (matchesDomainSpec rel . fst) $ zonePerms)

