{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main
where

import           Control.Exception (throwIO)
import           Data.Foldable (for_)
import qualified Data.Text as T
import           Network.HTTP.Client (newManager, defaultManagerSettings)
import           Network.Wai.Handler.Warp (testWithApplication)
import           Servant.Client
import           Test.HUnit (assertString)

import           PowerDNS.Client

import           PowerDNS.Guard.Server
import           PowerDNS.Guard.Config
import Test.HUnit.Lang
import GHC.Exception
import Data.CallStack
import Network.HTTP.Types (Status(statusCode))
import Test.Tasty
import Test.Tasty.HUnit (testCase)

data TestEnv = TestEnv
  { teGuardedEnv :: ClientEnv
  , teUpstreamEnv :: ClientEnv
  }

runGuardedAs :: T.Text -> ClientM a -> TestEnv -> IO (Either ClientError a)
runGuardedAs user act te  = runClientM act (applyXApiKey (user <> ":correctSecret") (teGuardedEnv te))

unsafeRunUpstream :: ClientM a -> TestEnv -> IO a
unsafeRunUpstream act te = either throwIO pure =<< runClientM act (teUpstreamEnv te)

note :: String -> Maybe a -> IO a
note err = maybe (fail err) pure

unsafeCleanZones :: TestEnv -> IO ()
unsafeCleanZones te = do
  zones <- unsafeRunUpstream (listZones "localhost" Nothing Nothing) te
  for_ zones $ \zone -> do
    name <- note "missing zone name" (zone_name zone)
    unsafeRunUpstream (deleteZone "localhost" name) te

srvName :: T.Text
srvName = "localhost"

ourZone :: T.Text
ourZone = "our.zone."

assertOk :: Either ClientError a -> Assertion
assertOk (Left r) = assertString ("request failed: " <> show r)
assertOk (Right _) = pure ()

assertForbidden :: Either ClientError a -> Assertion
assertForbidden = assertFailureCode 403 ""

assertUnauthenticated :: Either ClientError a -> Assertion
assertUnauthenticated = assertFailureCode 401 ""

location :: HasCallStack => Maybe SrcLoc
location = case reverse callStack of
  (_, loc) : _ -> Just loc
  [] -> Nothing

assertFailureCode :: Int -> String -> Either ClientError a -> Assertion
assertFailureCode _expectedCode prefix (Right _) = do
  assertString (prefix <> " unexpectedly produced a non-failure response")
assertFailureCode expectedCode prefix (Left err) = do
    case err of
        FailureResponse _req resp
            | actual == expected
            -> pure ()

            | otherwise
            -> let expectedMsg = "Status code: " <> show expectedCode
                   actualMsg = "Status code: " <> show (statusCode actual) <> ", message: " <> show (responseBody resp)
                   prefaceMsg | null prefix = Nothing
                              | otherwise = Just (prefix <> ": return code")
                in throwIO (HUnitFailure location $ ExpectedButGot prefaceMsg expectedMsg actualMsg)
          where
            expected = toEnum expectedCode
            actual = responseStatusCode resp
        r -> assertString (prefix <> ": returned with an unexpected error: " <> show r)

versionTests :: TestEnv -> TestTree
versionTests te = testGroup "Versions access"
  [ doubleTest "listing api versions" assertOk listVersions te
  ]

zoneTests :: TestEnv -> TestTree
zoneTests te = testGroup "Zone access"
  [ tripleTest "user-without-permissions" "listing zones" assertForbidden (listZones srvName Nothing Nothing) te
  , tripleTest "user-without-permissions" "creating a zone" assertForbidden (createZone srvName Nothing empty) te
  , tripleTest "user-without-permissions" "getting a zone" assertForbidden  (getZone srvName ourZone Nothing) te
  , tripleTest "user-without-permissions" "deleting a zone" assertForbidden (deleteZone srvName ourZone) te
  , testUpdatingRecords te
  , tripleTest "user-without-permissions" "updating a zone" assertForbidden (updateZone srvName ourZone empty) te
  , tripleTest "user-without-permissions" "triggering axfr" assertForbidden (triggerAxfr srvName ourZone) te
  , tripleTest "user-without-permissions" "notifying slaves" assertForbidden (notifySlaves srvName ourZone) te
  , tripleTest "user-without-permissions" "obtain axfr export" assertForbidden (getZoneAxfr srvName ourZone) te
  , tripleTest "user-without-permissions" "rectifying a zone" assertForbidden (rectifyZone srvName ourZone) te
  ]

type Asserter a = Either ClientError a -> Assertion

-- | Run this action first as unauthenticated, then as authenticated lacking any permission. The provided asserter is used for the authenticated user.
doubleTest :: String -> Asserter a -> ClientM a -> TestEnv -> TestTree
doubleTest title asserter action te = testGroup title
  [ testCase "without authentication" $ assertUnauthenticated =<< runUnauth action te
  , testCase "without permissions" $ asserter =<< runWithout action te
  ]

-- | Run this action first as unauthenticated, as authenticated lacking permission and finally as authenticated with some permissions. The provided
-- asserter is used when a user with some permission is used. For the other two cases 'assertForbidden' and 'assertUnauthenticated' are used.
tripleTest :: T.Text -> String -> Asserter a -> ClientM a -> TestEnv -> TestTree
tripleTest user title asserter action te = testGroup title
  [ testCase "without authentication" $ assertUnauthenticated =<< runUnauth action te
  , testCase "without permissions" $ assertForbidden =<< runWithout action te
  , testCase ("as " <> T.unpack user) $ asserter =<< runGuardedAs user action te
  ]

data Expected = ATXT
              | Any
              | None

testUpdatingRecords :: TestEnv -> TestTree
testUpdatingRecords te = testGroup "updating records" (mkTestCase <$> cases)
  where
    mkTestCase :: (T.Text, T.Text, Expected) -> TestTree
    mkTestCase (user, domain, expectancy) = testGroup (description <> " for domain " <> T.unpack domain) ts
      where
        description :: String
        description = case expectancy of
          ATXT -> "modify only A and TXT"
          Any -> "modify any record type"
          None -> "modify no record type"

        
        ts :: [TestTree]
        ts = case expectancy of
          ATXT -> [ withPresetZone' te $ tripleTest user "able to modify A records" assertOk (deleteRecords A domain) te
                  , withPresetZone' te $ tripleTest user "able to modify TXT records" assertOk (deleteRecords TXT domain) te
                  , withPresetZone' te $ tripleTest user "unable to modify AAAA records" assertForbidden (deleteRecords AAAA domain) te
                  ]
          None ->  [ withPresetZone' te $ tripleTest user "unable to modify A records" assertForbidden (deleteRecords A domain) te
                   , withPresetZone' te $ tripleTest user "unable to modify TXT records" assertForbidden (deleteRecords TXT domain) te
                   , withPresetZone' te $ tripleTest user "unable to modify AAAA records" assertForbidden (deleteRecords AAAA domain) te
                   ]
          Any ->  [ withPresetZone' te $ tripleTest user "able to modify A records" assertOk (deleteRecords A domain) te
                  , withPresetZone' te $ tripleTest user "able to modify TXT records" assertOk (deleteRecords TXT domain) te
                  , withPresetZone' te $ tripleTest user "able to modify AAAA records" assertOk (deleteRecords AAAA domain) te
                  ]

    deleteRecords :: RecordType -> T.Text -> ClientM ()
    deleteRecords ty na = () <$ updateRecords srvName ourZone (RRSets [changed])
      where
        changed :: RRSet
        changed = RRSet { rrset_name = na <> "." <> ourZone
                        , rrset_type = ty
                        , rrset_ttl = 1234
                        , rrset_changetype = Just Delete
                        , rrset_records = Just []
                        , rrset_comments = Just []
                        }
    -- List which record under our.zone. is expected to be modifiable via `user`.
    -- This list should be kept in sync with powerdns-guard.test.conf.
    cases :: [(T.Text, T.Text, Expected)]
    cases =
      [ ("user1", "sub.rec1", None)
      , ("user1", "rec1", ATXT)
      
      , ("user1", "sub.rec2", None)
      , ("user1", "rec2", Any)
      
      , ("user1", "sub.rec3", ATXT)
      , ("user1", "rec3", None)
      
      , ("user1", "sub.rec4", Any)
      , ("user1", "rec4", None)

      , ("user2", "sub.rec5", ATXT)
      , ("user2", "rec5", None)

      , ("user2", "sub.rec6", Any)
      , ("user2", "rec6", None)
      
      , ("user2", "sub.rec7", None)
      , ("user2", "rec7", ATXT)

      , ("user2", "sub.rec8", None)
      , ("user2", "rec8", Any)

      , ("user3", "sub.rec1", ATXT)
      , ("user4", "sub.rec1", ATXT)
      ]

-- | Version of 'withPresetZone' that does not provide the Zone to the action
withPresetZone' :: TestEnv -> TestTree -> TestTree
withPresetZone' te act = withPresetZone te (const act)

withPresetZone :: TestEnv -> (IO Zone -> TestTree) -> TestTree
withPresetZone te = withResource unsafeMakeZone unsafeDeleteZone
  where
    unsafeMakeZone = unsafeRunUpstream (createZone "localhost" (Just True) zone) te
    zone = empty { zone_name = Just ourZone
                 , zone_kind = Just Native
                 , zone_type = Just "zone"
                 , zone_rrsets = Just rrs
                 }

    rrs :: [RRSet]
    rrs = makeRecords "rec0"
       <> makeRecords "rec1"
       <> makeRecords "rec2"
       <> makeRecords "sub.rec3"
       <> makeRecords "sub.rec4"
       <> makeRecords "sub.rec5"
       <> makeRecords "sub.rec6"
       <> makeRecords "rec7"
       <> makeRecords "rec8"
       <> makeRecords "rec9"

    -- Generate A, AAAA and TXT records
    makeRecords :: T.Text -> [RRSet]
    makeRecords na = do
      (ty, re) <- [ (A, "127.0.0.1")
                  , (AAAA, "::1")
                  , (TXT, "\"some txt\"") ]
                  
      pure $ RRSet { rrset_name = (na <> "." <> ourZone)
                   , rrset_ttl = 86003
                   , rrset_type = ty
                   , rrset_changetype = Nothing
                   , rrset_records = Just [Record re False]
                   , rrset_comments = Nothing }
                                       
    unsafeDeleteZone :: Zone -> IO ()
    unsafeDeleteZone _z = () <$ unsafeRunUpstream (deleteZone "localhost" ourZone) te
  
runWithout :: ClientM a -> TestEnv -> IO (Either ClientError a)
runWithout act = runGuardedAs "user-without-permissions" act

runUnauth :: ClientM a -> TestEnv -> IO (Either ClientError a)
runUnauth act = runClientM act . teGuardedEnv

tests :: TestEnv -> TestTree
tests te = testGroup "PowerDNS tests"
    [ versionTests te
    , zoneTests te
    ] 

main :: IO ()
main = do
  cfg <- loadConfig "./test/powerdns-guard.test.conf"
  testWithApplication (mkApp cfg) $ \port -> do
    mgr <- newManager defaultManagerSettings 
    let guardedUrl = BaseUrl Http "127.0.0.1" port ""
        upstreamUrl = BaseUrl Http "127.0.0.1" 8081 ""
        guardedEnv = mkClientEnv mgr guardedUrl
        upstreamEnv = applyXApiKey "secret" (mkClientEnv mgr upstreamUrl)
        testEnv = TestEnv guardedEnv upstreamEnv
    
    unsafeCleanZones testEnv
    defaultMain (tests testEnv)

