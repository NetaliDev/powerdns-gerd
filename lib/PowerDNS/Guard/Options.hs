module PowerDNS.Guard.Options
  ( Command(..)
  , ServerOpts(..)
  , getCommand
  )
where

import Options.Applicative

data Command
  = CmdRunServer ServerOpts
  | CmdConfigHelp
  | CmdVersion

data ServerOpts = ServerOpts
  { optVerbosity :: Int
  , optConfig :: FilePath
  }

getCommand :: [String] -> IO Command
getCommand args = handleParseResult (execParserPure p optInfo args)
  where
    p = defaultPrefs{prefShowHelpOnError = True}

optInfo :: ParserInfo Command
optInfo = info (cmd <**> helper)
  ( fullDesc
  <> header "PowerDNS Guard - An authorization proxy for PowerDNS API"
  )

cmd :: Parser Command
cmd = subparser $ mconcat
  [ command "run-server" (info serverOpts (progDesc "Run the server" ))
  , command "config-help" (info (pure CmdConfigHelp) (progDesc "Display config help" ))
  , command "version" (info (pure CmdVersion) (progDesc "Display version"))
  ]

serverOpts :: Parser Command
serverOpts = (CmdRunServer <$> go) <**> helper
  where go = ServerOpts <$> parseVerbosity
                        <*> parseConfigFile

parseConfigFile :: Parser FilePath
parseConfigFile = option str ( metavar "FILE"
                            <> short 'c'
                            <> long "config"
                            <> help "Path to the config"
                            <> value "./powerdns-guard.conf"
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
