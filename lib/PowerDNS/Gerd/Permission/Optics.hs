{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE UndecidableInstances  #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module PowerDNS.Gerd.Permission.Optics
where

import PowerDNS.Gerd.Permission.Types

import Optics.TH


$(makeFieldLabelsNoPrefix ''PerZonePerms)
$(makeFieldLabelsNoPrefix ''ZonePerms)
$(makeFieldLabelsNoPrefix ''PermSet)
$(makeFieldLabelsNoPrefix ''ServerPerms)
