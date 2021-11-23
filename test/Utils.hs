module Utils
  ( hasStatus
  )
where

import Servant.Client
  
hasStatus :: Int -> Either ClientError a -> Bool
hasStatus i (Left (FailureResponse _req resp)) |
   responseStatusCode resp == toEnum i = True
hasStatus _i _        = False
