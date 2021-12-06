{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE UndecidableInstances  #-}
module PowerDNS.Gerd.User.Optics
where

import Optics.TH

import PowerDNS.Gerd.User.Types

$(makeFieldLabelsNoPrefix ''User)

