{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveGeneric #-}
module PowerDNS.Guard.API
  ( API
  , GuardedAPI(..)
  )
where

import qualified PowerDNS.API as PDNS
import Servant.API
import Servant.API.Generic
import Servant.Server.Experimental.Auth (AuthServerData)

import PowerDNS.Guard.Account

type instance AuthServerData (AuthProtect "xapi") = Account

type API = "api" :> "v1" :> ToServantApi GuardedAPI

data GuardedAPI f = GuardedAPI
  { servers :: f :- AuthProtect "xapi" :> ToServantApi PDNS.ServersAPI
  , zones :: f :- AuthProtect "xapi" :> ToServantApi PDNS.ZonesAPI
  , cryptokeys :: f :- AuthProtect "xapi" :> ToServantApi PDNS.CryptokeysAPI
  , metadata :: f :- AuthProtect "xapi" :> ToServantApi PDNS.MetadataAPI
  , tsigkeys :: f :- AuthProtect "xapi" :> ToServantApi PDNS.TSIGKeysAPI
  } deriving Generic
