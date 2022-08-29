-- |
-- Module: PowerDNS.Gerd.CmdVersion
-- Description: Version Command
--
-- This module defines the implementation of the @version@ subcommand of powerdns-gerd.
--
{-# LANGUAGE TemplateHaskell #-}
module PowerDNS.Gerd.CmdVersion
  ( runVersion
  )
where

import Data.Version (showVersion)
import Paths_powerdns_gerd (version)
import System.Exit (exitSuccess)

import Development.GitRev


runVersion :: IO ()
runVersion = putStrLn ourVersion >> exitSuccess

ourVersion :: String
ourVersion = unlines [ "version: " <> showVersion version
                     , "build: " <> git ]
  where
        branch :: String
        branch = $(gitBranch)


        git | branch == "UNKNOWN"
            = "No git information"
            | otherwise = branch
                       <> "@"
                       <> $(gitHash)
                       <> " (" <> $(gitCommitDate) <> ")"
                       <> dirty

        isDirty :: Bool
        isDirty = $(gitDirty)
        dirty | isDirty = " (uncommitted files present)"
              | otherwise   = ""
