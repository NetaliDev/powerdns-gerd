module PowerDNS.Guard.Utils
  ( const0
  , const1
  , const2
  , const3
  , const4
  , const5
  )
where

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
