{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
module PowerDNS.Guard.Utils
  ( const0
  , const1
  , const2
  , const3
  , const4
  , const5
  , parseAbsDomain
  , parseAbsDomainLabels
  , parseDomainPattern
  )
where

import           Control.Applicative (optional, some)
import qualified Data.Attoparsec.Text as ATT
import           Data.Char (isAsciiLower, isAsciiUpper, isDigit)
import           Data.List (intersperse)
import qualified Data.Text as T

import           Data.Foldable (asum)
import           PowerDNS.Guard.Permission

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

parseAbsDomain :: T.Text -> Either String T.Text
parseAbsDomain = ATT.parseOnly (absDomainP <* ATT.endOfInput)

parseAbsDomainLabels :: T.Text -> Either String DomainLabels
parseAbsDomainLabels = ATT.parseOnly (DomainLabels <$> relDomainLabelsP <* ATT.string "." <* ATT.endOfInput)

parseDomainPattern :: T.Text -> Either String DomainPattern
parseDomainPattern = ATT.parseOnly (domainPatternP <* ATT.endOfInput)

domainPatternP :: ATT.Parser DomainPattern
domainPatternP = DomainPattern <$> ((:) <$> domainLabelPatternInitP <*> some domainLabelPatternP)

domainLabelPatternInitP :: ATT.Parser DomainLabelPattern
domainLabelPatternInitP = asum [ DomLiteral <$> label <* ATT.string "."
                               , DomGlobStar <$ ATT.string "**."
                               , DomGlob <$ ATT.string "*." ]

domainLabelPatternP :: ATT.Parser DomainLabelPattern
domainLabelPatternP = asum [ DomLiteral <$> label <* ATT.string "."
                           , DomGlob <$ ATT.string "*." ]

absDomainP :: ATT.Parser T.Text
absDomainP = (<>) <$> relDomainP <*> ATT.string "."

relDomainLabelsP :: ATT.Parser [T.Text]
relDomainLabelsP = label `ATT.sepBy` ATT.string "."

relDomainP :: ATT.Parser T.Text
relDomainP = do
  r <- relDomainLabelsP
  pure (mconcat (intersperse "." r))

label :: ATT.Parser T.Text
label = do
  i <- letter1
  m <- optional letDigHyp1
  case m of
    Nothing -> pure i
    Just r | T.last r /= '-'
           -> pure (i <> r)
           | otherwise
           -> ((i <> r) <>) <$> letDig1

letter1 :: ATT.Parser T.Text
letter1 = ATT.takeWhile1 isAsciiLetter

-- | Parse 1 or more letters or digits
letDig1 :: ATT.Parser T.Text
letDig1 = ATT.takeWhile1 isLetDig

-- | Parse 1 or more letters, digits or hyphens
letDigHyp1 :: ATT.Parser T.Text
letDigHyp1 = ATT.takeWhile1 isLetDigHyp

isAsciiLetter :: Char -> Bool
isAsciiLetter c = isAsciiLower c || isAsciiUpper c

isLetDig :: Char -> Bool
isLetDig c = isAsciiLetter c || isDigit c

isLetDigHyp :: Char -> Bool
isLetDigHyp c = isLetDig c || c == '-'
