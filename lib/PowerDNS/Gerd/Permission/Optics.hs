{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
module PowerDNS.Gerd.Permission.Optics
where

import PowerDNS.Gerd.Permission.Types
import PowerDNS.Gerd.Utils


$(makeOurLenses "pzp" ''PerZonePerms)
$(makeOurLenses "zp" ''ZonePerms)
$(makeOurLenses "ps" ''PermSet)
$(makeOurLenses "sp" ''ServerPerms)
