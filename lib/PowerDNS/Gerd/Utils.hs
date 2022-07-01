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

import           Control.Monad.Logger (LogLevel(..), LogSource, LoggingT,
                                       filterLogger, runStdoutLoggingT)
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

runLog :: MonadIO m => Int -> LoggingT m a -> m a
runLog n = runStdoutLoggingT . filterLogger logFilter
  where
    logFilter :: LogSource -> LogLevel -> Bool
    logFilter _src lvl | n <= 0
                       = False

                       | otherwise
                       = lvl >= verbosity
      where
        verbosity = levels !! (n + 1)
        levels = LevelError : LevelWarn : LevelInfo : repeat LevelDebug

showT :: Show a => a -> T.Text
showT = T.pack . show
