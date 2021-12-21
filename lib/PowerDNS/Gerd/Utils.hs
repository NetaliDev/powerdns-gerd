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
  , parseAbsDomain
  , parseAbsDomainLabels
  , parseDomPat
  , logFilter
  , quoted
  , ourVersion
  , runLog
  )
where

import           Control.Applicative (many, optional)
import           Control.Monad.Logger (LogLevel(..), LogSource, LoggingT,
                                       filterLogger, runStdoutLoggingT)
import           Data.Char (isAsciiLower, isAsciiUpper, isDigit)
import           Data.Foldable (asum)
import           Data.Version (showVersion)

import qualified Data.Attoparsec.Text as ATT
import qualified Data.Text as T
import           Development.GitRev

import           Control.Monad.IO.Class (MonadIO)
import           Paths_powerdns_gerd (version)
import           PowerDNS.Gerd.Permission.Types

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

parseAbsDomain :: T.Text -> Either String T.Text
parseAbsDomain = ATT.parseOnly (absDomainP <* ATT.endOfInput)

parseAbsDomainLabels :: T.Text -> Either String DomainLabels
parseAbsDomainLabels = ATT.parseOnly (DomainLabels <$> relDomainLabelsP <* ATT.string "." <* ATT.endOfInput)

parseDomPat :: T.Text -> Either String DomPat
parseDomPat = ATT.parseOnly (domPatP <* ATT.endOfInput)

domPatP :: ATT.Parser DomPat
domPatP = DomPat <$> ((:) <$> domLabelPatInitP <*> many domLabelPatP)

domLabelPatInitP :: ATT.Parser DomLabelPat
domLabelPatInitP = asum [ DomLiteral <$> label <* ATT.string "."
                               , DomGlobStar <$ ATT.string "**."
                               , DomGlob <$ ATT.string "*." ]

domLabelPatP :: ATT.Parser DomLabelPat
domLabelPatP = asum [ DomLiteral <$> label <* ATT.string "."
                           , DomGlob <$ ATT.string "*." ]

absDomainP :: ATT.Parser T.Text
absDomainP = (<>) <$> relDomainP <*> ATT.string "."

relDomainLabelsP :: ATT.Parser [T.Text]
relDomainLabelsP = label `ATT.sepBy` ATT.string "."

relDomainP :: ATT.Parser T.Text
relDomainP = T.intercalate "." <$> relDomainLabelsP

label :: ATT.Parser T.Text
label = do
  i <- letDig1
  m <- optional letDigHyp1
  case m of
    Nothing -> pure i
    Just r | T.last r /= '-'
           -> pure (i <> r)
           | otherwise
           -> ((i <> r) <>) <$> letDig1

-- | Parse 1 or more letters or digits
letDig1 :: ATT.Parser T.Text
letDig1 = ATT.takeWhile1 isLetDig

-- | Parse 1 or more letters, digits or hyphens
letDigHyp1 :: ATT.Parser T.Text
letDigHyp1 = ATT.takeWhile1 isLetDigHyp

isAsciiLetter :: Char -> Bool
isAsciiLetter c = isAsciiLower c || isAsciiUpper c

isLetDig :: Char -> Bool
isLetDig c = isAsciiLetter c || isDigit c || (c == '_')

isLetDigHyp :: Char -> Bool
isLetDigHyp c = isLetDig c || c == '-'

logFilter :: Int -> LogSource -> LogLevel -> Bool
logFilter logVerbosity
    | logVerbosity <= 0 = \_ _ -> False
    | otherwise = \_ lvl -> lvl >= verbosity
    where
    verbosity = levels !! (logVerbosity + 1)
    levels = LevelError : LevelWarn : LevelInfo : repeat LevelDebug

pprDomPat :: DomPat -> T.Text
pprDomPat (DomPat patterns) = mconcat (pprLabelPattern <$> patterns)

pprLabelPattern :: DomLabelPat -> T.Text
pprLabelPattern (DomLiteral t) = t <> "."
pprLabelPattern DomGlob        = "*."
pprLabelPattern DomGlobStar    = "**."


showT :: Show a => a -> T.Text
showT = T.pack . show

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
runLog verbosity = runStdoutLoggingT . filterLogger (logFilter verbosity)
