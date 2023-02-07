{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main
where

import           Control.Exception (throwIO)
import           Data.Foldable (for_)
import           Data.List (groupBy, sortOn)
import           Data.Maybe (catMaybes, isJust)
import           System.Environment (lookupEnv)
import           System.Exit (exitFailure)
import           System.IO (BufferMode(..), hPutStrLn, hSetBuffering, stderr,
                            stdout)

import           Data.CallStack
import qualified Data.Text as T
import           Network.HTTP.Client (defaultManagerSettings, newManager)
import           Network.HTTP.Types (Status(statusCode))
import           Network.Wai.Handler.Warp (testWithApplication)
import           PowerDNS.Gerd.Config
import           PowerDNS.Gerd.Server
import           Servant.Client
import           Test.HUnit (assertString)
import           Test.HUnit.Lang
import           Test.Tasty
import           Test.Tasty.HUnit (testCase)

import           Control.Monad.Logger (defaultOutput, runLoggingT)
import           PowerDNS.API.Zones
import           PowerDNS.Client
import           UnliftIO (IOMode(AppendMode), SomeException, bracket, catch,
                           displayException, hClose, openFile)
import           UnliftIO.STM (newTVarIO)

data TestEnv = TestEnv
  { teGerdEnv :: ClientEnv
  , teUpstreamEnv :: ClientEnv
  }

runGerdAs :: T.Text -> ClientM a -> TestEnv -> IO (Either ClientError a)
runGerdAs user = runGerdWith user "correctSecret"

runGerdWith :: T.Text -> T.Text -> ClientM a -> TestEnv -> IO (Either ClientError a)
runGerdWith user pass act te = runClientM act (applyXApiKey (user <> ":" <> pass) (teGerdEnv te))

unsafeRunUpstream :: ClientM a -> TestEnv -> IO a
unsafeRunUpstream act te = either throwIO pure =<< runClientM act (teUpstreamEnv te)

note :: String -> Maybe a -> IO a
note err = maybe (fail err) pure

unsafeCleanZones :: TestEnv -> IO ()
unsafeCleanZones te = do
  zones <- unsafeRunUpstream (listZones "localhost" Nothing Nothing) te
  for_ zones $ \zone -> do
    name <- note "missing zone name" (zone_name zone)
    unsafeRunUpstream (deleteZone "localhost" (original name)) te

srvName :: T.Text
srvName = "localhost"

ourZone :: T.Text
ourZone = "our.zone."

assertOk :: Either ClientError a -> Assertion
assertOk (Left r)  = assertString ("request failed: " <> show r)
assertOk (Right _) = pure ()

assertForbidden :: Either ClientError a -> Assertion
assertForbidden = assertFailureCode 403 ""

assertUnauthenticated :: Either ClientError a -> Assertion
assertUnauthenticated = assertFailureCode 401 ""

location :: HasCallStack => Maybe SrcLoc
location = case reverse callStack of
  (_, loc) : _ -> Just loc
  []           -> Nothing

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

notifyAndRectifyTests :: TestEnv -> TestTree
notifyAndRectifyTests te = testGroup "Filtered rectify and notify" . fmap withZones $
    [ testCase "filtered rectify works when we have a permission" $
        assertOk =<< run (rectifyZone srvName zn)
    , testCase "filtered rectify is refused when we do not have a permission" $ do
        assertForbidden =<< runSomeoneElse (rectifyZone srvName zn2)
    , testCase "filtered notify works when we have a permission" $ do
        assertOk =<< run (notifySlaves srvName zn)
    , testCase "filtered notify is refused when we do not have a permission" $ do
        assertForbidden =<< runSomeoneElse (notifySlaves srvName zn2)
    ]
  where
    zn = "zone-notify-and-rectify."
    zn2 = "another-zone."

    runSomeoneElse x = runGerdWith "user-no-notify-and-rectify" "correctSecret" x te
    withZones = withSomeZone SomeZone
      { szName = zn
      , szRRsets = [ RRSet{ rrset_name = "foo.zone-notify-and-rectify."
                          , rrset_type = TXT
                          , rrset_ttl = Just 80000
                          , rrset_changetype = Nothing
                          , rrset_records = Just [Record "\"test-data\"" False]
                          , rrset_comments = Nothing } ]
      } te
    run x = runGerdWith "user-notify-and-rectify" "correctSecret" x te
data SomeZone = SomeZone
  { szName :: T.Text
  , szRRsets :: [RRSet]
  }

authnTests :: TestEnv -> TestTree
authnTests te = testGroup "User Authentication"
  [ testCase "without authentication" $ assertUnauthenticated =<< runUnauth listVersions te
  , testCase "with matching psk" $ assertOk =<< runGerdWith "user-psk" "correctSecret" listVersions te
  , testCase "with mismatching psk" $ assertUnauthenticated =<< runGerdWith "user-psk" "correctSecre" listVersions te
  , testCase "with matching hash" $ assertOk =<< runGerdWith "user-hash" "correctSecret" listVersions te
  , testCase "with mismatching hash" $ assertUnauthenticated =<< runGerdWith "user-hash" "correctSecre" listVersions te
  ]

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
  , testDomainMatrix te
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
  , testCase ("as " <> T.unpack user) $ asserter =<< runGerdAs user action te
  ]

data Expected = ATXT
              | Any
              | None

testDomainMatrix :: TestEnv -> TestTree
testDomainMatrix te = testGroup "updating records" $
    do (zone, domain, ownership) <- domainMatrix
       pure (testGroup ("on domain " <> T.unpack domain)
             (mkTestCases zone domain ownership =<< existingUsers))
  where
    mkTestCases :: T.Text -> T.Text -> Maybe (T.Text, Expected) -> T.Text -> [TestTree]
    mkTestCases zone domain ownership user =
        case ownership of
          Nothing                        -> casesForExpected user None
          Just (u, expected) | user == u -> casesForExpected user expected
                             | otherwise -> casesForExpected user None

      where
        casesForExpected :: T.Text -> Expected -> [TestTree]
        casesForExpected u expected = case expected of
            ATXT -> [ withPresetZones te $ testCase (prefix <> " able to modify A records") (assertOk =<< runGerdAs u (deleteRecords A domain) te)
                    , withPresetZones te $ testCase (prefix <> " able to modify TXT records") (assertOk =<< runGerdAs u (deleteRecords TXT domain) te)
                    , withPresetZones te $ testCase (prefix <> " unable to modify AAAA records") (assertForbidden =<< runGerdAs u (deleteRecords AAAA domain) te)
                    ]
            None -> [ withPresetZones te $ testCase (prefix <> " unable to modify A records") (assertForbidden =<< runGerdAs u (deleteRecords A domain) te)
                    , withPresetZones te $ testCase (prefix <> " unable to modify TXT records") (assertForbidden =<< runGerdAs u (deleteRecords TXT domain) te)
                    , withPresetZones te $ testCase (prefix <> " unable to modify AAAA records") (assertForbidden =<< runGerdAs u (deleteRecords AAAA domain) te)
                    ]
            Any ->  [ withPresetZones te $ testCase (prefix <> " able to modify A records") (assertOk =<< runGerdAs u (deleteRecords A domain) te)
                    , withPresetZones te $ testCase (prefix <> " able to modify TXT records") (assertOk =<< runGerdAs u (deleteRecords TXT domain) te)
                    , withPresetZones te $ testCase (prefix <> " able to modify AAAA records") (assertOk =<< runGerdAs u (deleteRecords AAAA domain) te)
                    ]
          where
            prefix = "user \"" <> T.unpack u <> "\""

        deleteRecords :: RecordType -> T.Text -> ClientM ()
        deleteRecords ty na = () <$ updateRecords srvName zone (RRSets [changed])
            where
                changed :: RRSet
                changed = RRSet { rrset_name = mkCIText na
                                , rrset_type = ty
                                , rrset_ttl = Just 1234
                                , rrset_changetype = Just Delete
                                , rrset_records = Just []
                                , rrset_comments = Just []
                                }

existingUsers :: [T.Text]
existingUsers = "user-without-permissions" : (fst <$> catMaybes (trd3 <$> domainMatrix))

-- | Each element represents a domain that will be created with
-- an A, AAAA and TXT record. The second part of the tuple states
-- the user that is expected to have modification power over that domain.
-- The Expected element defines what the user is expected to be able to modify.
--
-- This matrix must be kept in sync with powerdns-gerd.test.conf
domainMatrix :: [(T.Text, T.Text, Maybe (T.Text, Expected))]
domainMatrix =
  [ ("zone.", "rec1.user1.zone.", Just ("user1", ATXT))
  , ("zone.", "rec2.user1.zone.", Just ("user1", Any))
  , ("zone.", "unowned-a.user1.zone.", Nothing)
  , ("zone.", "sub.rec3.user1.zone.", Just ("user1", ATXT))
  , ("zone.", "sub.rec4.user1.zone.", Just ("user1", Any))

  -- Try working with wildcard records
  , ("zone.", "*.rec4.user1.zone.", Just ("user1", Any))

  , ("zone.", "rec5.user1.zone.", Just ("user1", ATXT))
  , ("zone.", "rec6.user1.zone.", Just ("user1", Any))
  , ("zone.", "unowned-b.user1.zone.", Nothing)
  , ("zone.", "sub.rec7.user1.zone.", Just ("user1", ATXT))
  , ("zone.", "sub.rec8.user1.zone.", Just ("user1", Any))

  , ("zone.", "globstar.user2.zone.", Nothing)
  , ("zone.", "sub.globstar.user2.zone.", Just ("user2", ATXT))
  , ("zone.", "sub.sub.globstar.user2.zone.", Just ("user2", ATXT))
  , ("zone.", "alpha.glob.user2.zone.", Nothing)
  , ("zone.", "sub.alpha.glob.user2.zone.", Just ("user2", ATXT))
  ]



fst3 :: (a, b, c) -> a
fst3 (a, _, _) = a

snd3 :: (a, b, c) -> b
snd3 (_, b, _) = b

trd3 :: (a, b, c) -> c
trd3 (_, _, c) = c

withSomeZone :: SomeZone -> TestEnv -> TestTree -> TestTree
withSomeZone sz te t = withResource unsafeMakeZone unsafeDeleteZone (const t)
  where
    unsafeDeleteZone _ = () <$ unsafeRunUpstream (deleteZone "localhost" (szName sz)) te
    unsafeMakeZone = () <$ unsafeRunUpstream (createZone "localhost" (Just True) zone) te
    zone :: Zone
    zone = empty { zone_name = Just (mkCIText (szName sz))
                 , zone_kind = Just Native
                 , zone_type = Just "zone"
                 , zone_rrsets = Just (szRRsets sz)
                 }

withPresetZones :: TestEnv -> TestTree -> TestTree
withPresetZones te t = withResource unsafeMakeZones unsafeDeleteZones (const t)
  where

    byZones :: [[(T.Text, T.Text, Maybe (T.Text, Expected))]]
    byZones = groupBy (\l r -> fst3 l == fst3 r) (sortOn fst3 domainMatrix)

    unsafeMakeZones = for_ byZones $ \z -> do
        let zoneName = fst3 (z !! 0)
            zone :: Zone
            zone = empty { zone_name = Just (mkCIText zoneName)
                         , zone_kind = Just Native
                         , zone_type = Just "zone"
                         , zone_rrsets = Just $ makeRecords =<< (snd3 <$> z)
                         }
        unsafeRunUpstream (createZone "localhost" (Just True) zone) te

    -- Generate A, AAAA and TXT records
    makeRecords :: T.Text -> [RRSet]
    makeRecords na = do
      (ty, re) <- [ (A, "127.0.0.1")
                  , (AAAA, "::1")
                  , (TXT, "\"some txt\"") ]

      pure $ RRSet { rrset_name = mkCIText na
                   , rrset_ttl = Just 86003
                   , rrset_type = ty
                   , rrset_changetype = Nothing
                   , rrset_records = Just [Record re False]
                   , rrset_comments = Nothing }

    unsafeDeleteZones :: () -> IO ()
    unsafeDeleteZones _ = for_ byZones $ \zone -> do
        let zoneName = fst3 (zone !! 0)
        () <$ unsafeRunUpstream (deleteZone "localhost" zoneName) te

runWithout :: ClientM a -> TestEnv -> IO (Either ClientError a)
runWithout act = runGerdAs "user-without-permissions" act

runUnauth :: ClientM a -> TestEnv -> IO (Either ClientError a)
runUnauth act = runClientM act . teGerdEnv

tests :: TestEnv -> TestTree
tests te = testGroup "PowerDNS tests"
    [ versionTests te
    , authnTests te
    , notifyAndRectifyTests te
    , zoneTests te
    ]

configErr :: SomeException -> IO a
configErr e = do
  hPutStrLn stderr (displayException e)
  exitFailure

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering
  mgr <- newManager defaultManagerSettings
  let gerdUrl = BaseUrl Http "127.0.0.1" 9000 ""
      gerdEnv = mkClientEnv mgr gerdUrl
      upstreamUrl = BaseUrl Http "127.0.0.1" 8081 ""
      upstreamEnv = applyXApiKey "secret" (mkClientEnv mgr upstreamUrl)
      testEnv = TestEnv gerdEnv upstreamEnv

  unsafeCleanZones testEnv
  defaultMain (tests testEnv)
