{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeOperators       #-}
module PowerDNS.Gerd.Server
  ( mkApp
  )
where

import           Data.Char (ord)

import           Control.Monad.Logger (LoggingT, filterLogger, logError,
                                       runStdoutLoggingT)
import           Control.Monad.Trans.Except (ExceptT(ExceptT))
import           Control.Monad.Trans.Reader (runReaderT)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Text.Encoding.Error (lenientDecode)
import           Network.HTTP.Client (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.Wai (Request(requestHeaders))
import qualified PowerDNS.Client as PDNS
import           PowerDNS.Gerd.User
import           Servant (Context(..), throwError)
import           Servant.Client (parseBaseUrl)
import           Servant.Client.Streaming (mkClientEnv)
import           Servant.Server (Application, Handler(..), ServerError(..),
                                 err400, err401, err500)
import           Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import           Servant.Server.Generic (genericServeTWithContext)
import           UnliftIO (MonadIO, liftIO)
import qualified UnliftIO.Exception as E

import qualified Data.Map as M
import           PowerDNS.Gerd.Config (Config(..))
import           PowerDNS.Gerd.Server.Endpoints
import           PowerDNS.Gerd.Types
import           PowerDNS.Gerd.Utils


runLog :: MonadIO m => Int -> LoggingT m a -> m a
runLog verbosity = runStdoutLoggingT . filterLogger (logFilter verbosity)

-- | A natural transformation turning a GerdM into a plain Servant handler.
-- See https://docs.servant.dev/en/stable/cookbook/using-custom-monad/UsingCustomMonad.html
-- One of the core themes is that we want an unliftable monad. Inside GerdM we throw
-- ServerError as an exception, and this handler catches them back. We also
-- catch outstanding exceptions and produce a 500 error here instead. This allows
-- middlewares to log these requests and responses as well.
toHandler :: Env -> GerdM a -> Handler a
toHandler env = Handler . ExceptT . flip runReaderT env . runLog (envVerbosity env) . runGerdM . catchRemEx
  where
    catchRemEx :: forall a. GerdM a -> GerdM (Either ServerError a)
    catchRemEx handler = (Right <$> handler) `E.catches` exceptions

    exceptions :: [E.Handler GerdM (Either ServerError a)]
    exceptions = [ E.Handler prpgSrvErr
                , E.Handler handleAnyException
                ]

    handleAnyException :: E.SomeException -> GerdM (Either ServerError a)
    handleAnyException ex = do
        logException ex
        pure (Left (err500 {errBody = "Internal error"}))

    logException :: E.SomeException -> GerdM ()
    logException ex = do
        $logError "Unhandled exception"
        $logError (T.pack (E.displayException ex))

    -- Propagate any thrown ServerError as Left for Servant.
    prpgSrvErr :: ServerError -> GerdM (Either ServerError a)
    prpgSrvErr = pure . Left

mkApp :: Int -> Config -> IO Application
mkApp verbosity cfg = do
  url <- parseBaseUrl (T.unpack (cfgUpstreamApiBaseUrl cfg))
  mgr <- newManager tlsManagerSettings
  let clientEnv =  PDNS.applyXApiKey (cfgUpstreamApiKey cfg) (mkClientEnv mgr url)
  let env = Env clientEnv verbosity

  pure (genericServeTWithContext (toHandler env) server (ourContext cfg))

-- | A custom authentication handler as per https://docs.servant.dev/en/stable/tutorial/Authentication.html#generalized-authentication
authHandler :: Config -> AuthHandler Request User
authHandler cfg = mkAuthHandler handler
  where
    db :: M.Map Username User
    db = cfgUsers cfg

    note401 :: Maybe a -> BSL.ByteString -> Handler a
    note401 m reason = maybe (throw401 reason) pure m

    throw401 :: BSL.ByteString -> Handler a
    throw401 msg = throwError (err401 { errBody = msg })

    throw400 :: BSL.ByteString -> Handler a
    throw400 msg = throwError (err400 { errBody = msg })

    decodeLenient = T.decodeUtf8With lenientDecode

    handler req = do
        apiKey <- lookup "X-API-Key" (requestHeaders req) `note401` "Missing API key"
        case BS.split (fromIntegral (ord ':')) apiKey of
            [user, hash] -> do mUser <- liftIO $ authenticate db (decodeLenient user) hash
                               mUser `note401` "Bad authentication"
            _            -> throw400 "Invalid X-API-Key syntax"


type CtxtList = AuthHandler Request User ': '[]
ourContext :: Config -> Context CtxtList
ourContext cfg = authHandler cfg :. EmptyContext
