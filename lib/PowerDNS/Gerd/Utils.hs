-- |
-- Module: PowerDNS.Gerd.Utils
-- Description: Various utilities
--
-- This module defines an assortment of utilities used by powerdns-gerd.
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module PowerDNS.Gerd.Utils
  ( const0
  , const1
  , const2
  , const3
  , const4
  , const5
  , hush
  , quoted
  , ourVersion
  , runLog
  , showT
  )
where

import           Control.Concurrent (myThreadId)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (LogLevel(..), LogSource, LoggingT(..),
                                       filterLogger, runStdoutLoggingT,
                                       toLogStr)
import           Data.Version (showVersion)

import qualified Data.Text as T
import           Development.GitRev

import           Control.Monad.IO.Class (MonadIO)
import           Paths_powerdns_gerd (version)

const0 :: a -> a
const0 a = a

const1 :: a -> b -> a
const1 a _ = a

const2 :: a -> b -> c -> a
const2 a _ _ = a

const3 :: a -> b -> c -> d -> a
const3 a _ _ _ = a

const4 :: a -> b -> c -> d -> e -> a
const4 a _ _ _ _ = a

const5 :: a -> b -> c -> d -> e -> f -> a
const5 a _ _ _ _ _ = a

hush :: Either a b -> Maybe b
hush = either (const Nothing) Just

quoted :: T.Text -> T.Text
quoted x = "\"" <> x <> "\""

ourVersion :: String
ourVersion = unlines [ "version: " <> showVersion version
                     , "build: "   <> $(gitBranch)
                                   <> "@"
                                   <> $(gitHash)
                                   <> " (" <> $(gitCommitDate) <> ")"
                                   <> dirty

                     ]
  where
        dirty | $(gitDirty) = " (uncommitted files present)"
              | otherwise   = ""

getTid :: MonadIO m => m String
getTid = drop 9 . show <$> liftIO myThreadId

includeTid :: MonadIO m => LoggingT m a -> LoggingT m a
includeTid (LoggingT act) = LoggingT $ \logger -> act $ \loc src lvl str -> do
  tid <- getTid
  let pref = toLogStr ("[" <> tid <> "] ")
  logger loc src lvl (pref <> str)

runLog :: MonadIO m => Int -> LoggingT m a -> m a
runLog n = runStdoutLoggingT . includeTid . filterLogger logFilter
  where
    logFilter :: LogSource -> LogLevel -> Bool
    logFilter _src lvl | n <= 0
                       = False

                       | otherwise
                       = lvl >= verbosity
    verbosity = levels !! n
    levels = LevelError : LevelWarn : LevelInfo : repeat LevelDebug

showT :: Show a => a -> T.Text
showT = T.pack . show
