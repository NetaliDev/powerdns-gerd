{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
module PowerDNS.Guard.Utils
  ( const0
  , const1
  , const2
  , const3
  , const4
  , const5
  , parseAbsDomain
  , parseRelDomain
  , parseRelDomainSpec
  , parseAbsDomainSpec
  )
where

import qualified Data.Text as T
import qualified Data.Attoparsec.Text as ATT
import Control.Applicative (optional)
import Data.List (intersperse)
import Data.Char (isAsciiLower, isAsciiUpper, isDigit)

import PowerDNS.Guard.Permission
import Data.Foldable (asum)

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

parseRelDomain :: T.Text -> Either String T.Text
parseRelDomain = ATT.parseOnly (relDomainP <* ATT.endOfInput)

parseRelDomainSpec :: T.Text -> Either String (DomainSpec Relative)
parseRelDomainSpec = ATT.parseOnly $ asum
  [ AnyDomain <$ (ATT.string "*" <* ATT.endOfInput)
  , HasSuffix . Domain <$> ATT.string "*." <* relDomainP <* ATT.endOfInput
  , ExactDomain . Domain <$> relDomainP <* ATT.endOfInput
  ]

parseAbsDomainSpec :: T.Text -> Either String (DomainSpec Absolute)
parseAbsDomainSpec = ATT.parseOnly $ asum
  [ AnyDomain <$ (ATT.string "*" <* ATT.endOfInput)
  , HasSuffix . Domain <$> ATT.string "*." <* relDomainP <* ATT.endOfInput
  , ExactDomain . Domain <$> absDomainP <* ATT.endOfInput
  ]

absDomainP :: ATT.Parser T.Text
absDomainP = (<>) <$> relDomainP <*> ATT.string "."

relDomainP :: ATT.Parser T.Text
relDomainP = do
  r <- label `ATT.sepBy` ATT.string "."
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
