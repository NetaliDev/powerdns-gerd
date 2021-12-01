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
                     , "build: "   <> $(gitBranch)
                                   <> "@"
                                   <> $(gitHash)
                                   <> " (" <> $(gitCommitDate) <> ")"
                                   <> dirty

                     ]
  where
        dirty | $(gitDirty) = " (uncommitted files present)"
              | otherwise   = ""
