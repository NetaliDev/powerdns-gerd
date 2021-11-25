{-# LANGUAGE DataKinds     #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeFamilies  #-}
{-# LANGUAGE TypeOperators #-}
module PowerDNS.Guard.API
  ( API
  , api
  , GuardedAPI(..)
  )
where

import qualified PowerDNS.API as PDNS
import           Servant.API
import           Servant.API.Generic
import           Servant.Server.Experimental.Auth (AuthServerData)

import           Data.Proxy
import           PowerDNS.Guard.User

type instance AuthServerData (AuthProtect "xapi") = User

type API = ToServantApi GuardedAPI

api :: Proxy API
api = Proxy

data GuardedAPI f = GuardedAPI
  { versions   :: f :- AuthProtect "xapi" :> "api" :> ToServantApi PDNS.VersionsAPI
  , servers    :: f :- AuthProtect "xapi" :> "api" :> "v1" :> ToServantApi PDNS.ServersAPI
  , zones      :: f :- AuthProtect "xapi" :> "api" :> "v1" :> ToServantApi PDNS.ZonesAPI
  , cryptokeys :: f :- AuthProtect "xapi" :> "api" :> "v1" :> ToServantApi PDNS.CryptokeysAPI
  , metadata   :: f :- AuthProtect "xapi" :> "api" :> "v1" :> ToServantApi PDNS.MetadataAPI
  , tsigkeys   :: f :- AuthProtect "xapi" :> "api" :> "v1" :> ToServantApi PDNS.TSIGKeysAPI
  } deriving Generic
