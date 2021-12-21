-- |
-- Module: PowerDNS.Gerd.Options
-- Description: Runtime option parser
--
-- This module defines the option parser to handle the various runtime flags and
-- commands that powerdns-accepts.
--
module PowerDNS.Gerd.Options
  ( Command(..)
  , ServerOpts(..)
  , DigestOpts(..)
  , getCommand
  )
where

import Options.Applicative

import Data.List (intercalate)
import Data.Maybe (fromMaybe)
import Data.Tuple (swap)
import PowerDNS.Gerd.User.Types (MemLimit(..), OpsLimit(..))

data Command
  = CmdServer ServerOpts
  | CmdConfigHelp
  | CmdConfigValidate FilePath
  | CmdVersion
  | CmdDigest DigestOpts

data ServerOpts = ServerOpts
  { optVerbosity :: Int
  , optConfig :: FilePath
  }

data DigestOpts = DigestOpts
  { doMemLimit :: MemLimit
  , doOpsLimit :: OpsLimit
  }

getCommand :: [String] -> IO Command
getCommand args = handleParseResult (execParserPure p optInfo args)
  where
    p = defaultPrefs{prefShowHelpOnError = True}

optInfo :: ParserInfo Command
optInfo = info (cmd <**> helper)
  ( fullDesc
  <> header "PowerDNS Gerd - An authorization proxy for PowerDNS API"
  )

cmd :: Parser Command
cmd = subparser $ mconcat
  [ command "server" (info cmdServer (progDesc "Run the server" ))
  , command "config-help" (info (pure CmdConfigHelp) (progDesc "Display config help" ))
  , command "config-validate" (info cmdConfigValidate (progDesc "Validate config file"))
  , command "digest" (info cmdDigest (progDesc "Digest a password"))
  , command "version" (info (pure CmdVersion) (progDesc "Display version"))
  ]

cmdConfigValidate :: Parser Command
cmdConfigValidate = CmdConfigValidate <$> (parseConfigFile <**> helper)

cmdDigest :: Parser Command
cmdDigest = CmdDigest <$> (go <**> helper)
  where go = DigestOpts <$> parseMemLimit
                        <*> parseOpsLimit

parseMemLimit :: Parser MemLimit
parseMemLimit = option (maybeReader reader) ( short 'm'
                                           <> long "mem-limit"
                                           <> help ("Argon memory limit. Choices are: " <> choices)
                                           <> value MemModerate
                                           <> showDefaultWith ppr)

  where
    vals = [ ("min", MemMin)
           , ("interactive", MemInteractive)
           , ("moderate", MemModerate)
           , ("sensitive", MemSensitive)
           , ("max", MemMax)
           ]

    choices = intercalate ", " (fst <$> vals)

    ppr x = fromMaybe "Unknown" (lookup x (swap <$> vals))

    reader :: String -> Maybe MemLimit
    reader = (`lookup` vals)

parseOpsLimit :: Parser OpsLimit
parseOpsLimit = option (maybeReader reader) ( short 'm'
                                           <> long "ops-limit"
                                           <> help ("Argon ops limit. Choices are: " <> choices)
                                           <> value OpsModerate
                                           <> showDefaultWith ppr)

  where
    vals = [ ("min", OpsMin)
           , ("interactive", OpsInteractive)
           , ("moderate", OpsModerate)
           , ("sensitive", OpsSensitive)
           , ("max", OpsMax)
           ]

    choices = intercalate ", " (fst <$> vals)
    ppr x = fromMaybe "Unknown" (lookup x (swap <$> vals))

    reader :: String -> Maybe OpsLimit
    reader = (`lookup` vals)

cmdServer :: Parser Command
cmdServer = (CmdServer <$> go) <**> helper
  where go = ServerOpts <$> parseVerbosity
                        <*> parseConfigFile

parseConfigFile :: Parser FilePath
parseConfigFile = option str ( metavar "FILE"
                            <> short 'c'
                            <> long "config"
                            <> help "Path to the config"
                            <> value "./powerdns-gerd.conf"
                            <> showDefault)

parseVerbosity :: Parser Int
parseVerbosity = quiet <|> level <|> pure 1
  where
    level :: Parser Int
    level = (fmap length . some)
            (flag' () (long "verbosity" <> short 'v' <> help "Increase verbosity"))

    quiet :: Parser Int
    quiet = flag' 0 (short 'q'
                  <> long "quiet"
                  <> help "Disable all logging.")
