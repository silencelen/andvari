# The hostile-server harness

The trust design (`docs/design/2026-11-15-onboarding-trust.md`) claims that the server need not be trusted. This module
tests that claim end to end: a proxy sits between the **real** client engine (`:core`, driven by the headless host of
`:tools:andvari-cli`) and the **real** server in its test mode, and lies, withholds, replays, forks, swaps and races.
Each test states one thing the design says a client must do in response, and names the design section it comes from.

Tests only. Nothing here ships, and nothing here patches the engine or the server: where they do not behave as the
design says, the test stays exactly as the design demands and is marked `@Ignore("FINDING Hn: …")`.

```
./gradlew :tools:hostile-harness:test          # about four minutes; every test starts its own server
```

## Layout

| File (under `src/test/kotlin/io/silencelen/andvari/hostile/`) | What it is |
|---|---|
| `proxy/HostileProxy.kt` | The proxy: listeners, rules, the recording, and the handlers a rule is made of. |
| `proxy/Wire.kt` | JSON surgery, signed frames read from the outside, and the two big lies: `serveLog` and `serveCards`. |
| `World.kt` | One scenario's world: server, proxy, devices; restart of a device; the list of secret-carrying routes. |
| `Adversary.kt` | The adversaries that hold a key: T1 as the operator (cards), a member working with T1 (log entries). |
| `ProxySelfTest.kt` | The proxy's own behaviours, each against the real server. |
| `PasswordRuleTest.kt`, `CardForkTest.kt`, `WithholdingTest.kt`, `EquivocationTest.kt`, `DeviceLinkTest.kt`, `LinkTest.kt`, `SwappedEnvelopeTest.kt`, `RecoveryTest.kt`, `AccountStateTest.kt`, `PinRulesTest.kt`, `AnswerCapsTest.kt`, `SessionEndTest.kt`, `BellFrameTest.kt`, `LyingAnswersTest.kt`, `RedirectTest.kt`, `KeyMaterialTest.kt`, `LogReplayTest.kt`, `BellLiesTest.kt` | The scenarios. |
| `proxy/HostileBell.kt` | The hostile event bell: a raw WebSocket server on a real loopback socket, for the scenarios on the bell's frames. |

## The proxy

- **Every device dials a listener of its own** (`World.device(tag)`), so the proxy knows who is asking and can show
  different devices different things. The instance's origin names a port that answers nothing (each connection is
  closed) unless a test routes it to the proxy (`World.originListener`): a device reaches the server only through the
  proxy, so the recording is complete. What is not in it never left a device.
- **No port is picked before it is bound.** The origin's port is the test server's relay, bound to port 0 when the
  server is made and held to the end; the server's own listener, every listener of the proxy and the hostile bell bind
  port 0 too. The origin is routed to the proxy with `TestServer.interpose`, never by binding a port picked earlier
  (another process on a busy machine could take it in between, which cost two runs on 2026-11-16).
- **Recording.** Every request is recorded whole, body included, before any rule runs (`proxy.requests(route, tag, since)`),
  with what the real server answered and what the device was served.
- **Rules** (`proxy.on(route, tag, times, where) { … }`): the newest matching rule handles a request; anything no rule
  claims passes untouched. A rule can pass, drop (no answer; with or without the server having acted), answer a chosen
  status, stream an endless or oversized body (`Endless`, counting what the device let it write in `Exchange.written`),
  hold a request or an answer at a `Gate` until the test releases it (every race is two of these), replay an
  earlier answer, substitute a body or one JSON field, change the request on its way in, forward twice, and ask the real
  server anything else with the caller's own credentials.
- **A lie must reach the device.** The item engine pulls `/sync` deltas: a page carries only the vault, grant and item
  rows that changed since the device's cursor (spec 03 §4). A rule that edits a row the page does not carry changes
  nothing, so the lying rules put the row in (`fullSyncPage`, `withRowsFrom`; `serveLog` does it for the vault row),
  and `serveVaultRows` is how a server that stops lying shows the true row again (an honest delta would not resend it).
  Where a scenario depends on the lie arriving, it asserts that it did (a log fetch, a swapped row count).
- **WebSocket: refused, not passed through.** The engine as the headless host drives it never opens `/api/v1/events`;
  it learns of changes by asking. An upgrade request is answered `501` and recorded, so a test would see one. The
  scenarios on the bell itself run the engine's `EventBell` in the test and send its socket to `HostileBell` instead.
- A rule that throws is a mistake in the test, never an answer: the scenario fails.

## Coverage

Status: **pass**, or the finding that keeps the test ignored.

### The password rule and trust on first use (§4.4, §8.2 step 0, §10, §9.3; R22, T2-B1, FS-B1)

| Rule | Test | Status |
|---|---|---|
| A device link from an unpinned origin: no prelogin, claim or pickup before the Trust Gate is accepted; a declined gate sends nothing and pins nothing (§17 flow conformance) | `PasswordRuleTest.aDeviceLinkFromAnUnpinnedOriginSendsNoPreloginClaimOrPickupBeforeTheTrustGateIsAccepted` | pass |
| A `/d` link that did not come through "Link from your other device" starts nothing: no request at all, pinned or not | `PasswordRuleTest.aDeviceLinkThatDidNotArriveThroughTheLinkDeviceScreenStartsNothingAtAll` | pass |
| Sign-in sends no prelogin and no `authKey` with no pin, or through an enrol, link-offer or kit pin; a kit pin does not count for a device link | `PasswordRuleTest.signingInSendsNoPreloginAndNoAuthKeyThroughAPinThatIsNotAPasswordPin` | pass |
| A setup pin counts only for the operator account it enrolled | `PasswordRuleTest.aSetupPinLetsOnlyItsOwnOperatorAccountSignIn` | pass |
| A kit starts nothing outside its own screen; on it, no `recoveryAuthKey` before the person confirmed the target; a cancelled recovery leaves no pin; a typed kit shows the Trust Gate | `PasswordRuleTest.aRecoveryKitStartsNothingOutsideItsOwnScreenAndSendsNoProofBeforeThePersonConfirmsTheTarget` | pass |
| A kit whose `card0Hash` is not the served card 0 falls back to the Trust Gate with the warning | `PasswordRuleTest.aKitWhoseCardZeroIsNotTheServedOneFallsBackToTheTrustGateBeforeAnyProofIsSent` | pass |
| Assisted recovery opens no request before the Trust Gate; a kit pin does not stand in for it | `PasswordRuleTest.assistedRecoveryOpensNoRequestBeforeTheTrustGateAndAKitPinDoesNotStandInForIt` | pass |

### The instance card (§4.4, §4.6, §2.4 "Pinning"; R22, R30, R36)

| Rule | Test | Status |
|---|---|---|
| Another hash at the pinned `seq` is a fork: every flow stops, the instance is sent nothing, the fork outlives a restart and the server turning honest, and only "Forget this server" goes on | `CardForkTest.anotherCardAtThePinnedPositionIsAForkThatStopsEveryFlowSurvivesARestartAndOnlyForgettingTheServerGoesOn` | pass |
| Under a fork the signed-in account sends no sync and no write | `CardForkTest.afterAForkTheSignedInAccountSendsNoSyncAndNoWrite` | **H1** |
| Under a fork the item engine answers `halted` and sends nothing on an item route, also after a restart (H1's item half) | `CardForkTest.afterAForkTheItemEngineSendsNothingOnAnItemRoute` | pass |
| An ordinary sync judges the served chain against the pin; the sync answers `halted` and asked only for the chain | `CardForkTest.anOrdinarySyncNoticesAForkedCardChain` | pass (was H2) |
| A new card 0 after an operator reset is a fork at once; the empty chain before it is only withheld | `CardForkTest.aNewCardZeroAfterAnOperatorResetIsAForkAndTheEmptyChainBeforeItOnlyWithheld` | pass |
| Another instance's genuine chain at a pinned origin is a fork | `CardForkTest.anotherInstancesGenuineChainServedAtAPinnedOriginIsAFork` | pass |
| A look-alike address serving the genuine chain is `origin_mismatch` for the typed address, a kit, a device link and an invite; nothing is pinned and only public reads reach it | `CardForkTest.aLookAlikeAddressServingTheGenuineChainIsOriginMismatchForEveryRootAndGetsNoSecret` | pass |
| A signed move is followed only by the person's one tap | `CardForkTest.aSignedMoveIsFollowedOnlyByThePersonsOneTap` | pass |
| A `kind` change is never followed silently; a card that also moves is a `kind` change first | `CardForkTest.aKindChangeIsNeverFollowedSilentlyAndACardThatAlsoMovesIsAKindChangeFirst` | pass |
| A store build never follows a move or a `kind` change of the baked instance (trust engine built as a store build would; the host has no baked instance) | `CardForkTest.aStoreBuildNeverFollowsAMoveOrAKindChangeOfTheBakedInstance` | pass |

### Account deletion's leaves (§3.11, FS-R7)

| Rule | Test | Status |
|---|---|---|
| A far-future head the device never verified stops the deletion before anything is signed, derived or sent | `DeletionTest.aFarFutureHeadBobNeverVerifiedStopsTheDeletionBeforeAnythingIsSignedOrSent` | pass |
| A far-future time beside a head the device verified is ignored; the leave carries the device's own time | `DeletionTest.aFarFutureTimeOnAHeadBobVerifiedIsIgnoredAndTheLeaveCarriesHisOwnTime` | pass |
| A chain below the pin (or empty) is `withheld`, not a stop; a device with no newer pin sees stale, genuine state | `WithholdingTest.aCardChainServedBelowThePinIsWithheldAndStopsNothing` | pass |

### The vault log: withholding and rollback (§3.6 (e), §3.8, §3.9; R20)

| Rule | Test | Status |
|---|---|---|
| A head below the verified head is withholding: the device keeps its state, reads on, writes nothing; durable | `WithholdingTest.aVaultLogServedBelowTheVerifiedHeadIsWithheldAndTheDeviceKeepsItsOwnState` | pass |
| When the server serves the verified head again, the device is in order | `WithholdingTest.aWithheldVaultIsInOrderAgainWhenTheServerServesTheVerifiedHeadAgain` | pass (was H3) |
| When the server serves beyond the verified head, the device catches up | `WithholdingTest.aWithheldVaultLogIsInOrderAgainOnceTheServerServesBeyondTheVerifiedHead` | pass |
| A device that holds no newer head sees stale but genuine state, and catches up | `WithholdingTest.aHiddenLogEntryLeavesADeviceThatHoldsNoNewerHeadOnStaleButGenuineState` | pass |
| An entry nobody signed is refused; the verified state stays; writes wait until the log verifies again | `WithholdingTest.aLogEntryNobodySignedIsRefusedTheVerifiedStateStaysAndWritesWaitUntilTheLogVerifiesAgain` | pass |
| A failed log is in order again when the genuine log is served (the failing entry lay beyond the genuine head) | `WithholdingTest.aVaultWhoseLogFailedOnAnEntryBeyondTheGenuineHeadIsInOrderAgainWhenTheGenuineLogIsServed` | pass (was H3) |
| A log below the account's own vault record is withheld on a fresh device, and the vault is not adopted | `WithholdingTest.aLogServedBelowTheAccountsVaultRecordIsWithheldOnAFreshDeviceOfTheAccount` | pass |
| A claimed purge without the owner's signed `delete` changes nothing | `WithholdingTest.aClaimedPurgeWithoutTheOwnersSignedDeleteDoesNotMakeADeviceGiveUpTheVault` | pass |
| A hidden link answer leaves both sides unconfirmed until it is served | `WithholdingTest.aHiddenLinkAnswerLeavesBothSidesUnconfirmedUntilItIsServed` | pass |

### Equivocation (§3.7, §3.9; R21)

| Rule | Test | Status |
|---|---|---|
| Two genuine entries at one position freeze the vault: read-only with copy-out, and frozen across a restart | `EquivocationTest.aDeviceShownTwoGenuineEntriesAtOnePositionFreezesTheVaultAndStaysFrozenAcrossARestart` | pass |
| A device that sees only one branch cannot tell; shown the other, it freezes | `EquivocationTest.aDeviceThatSeesOnlyOneBranchCannotTellAndFreezesOnceItIsShownTheOther` | pass |
| A branch that contradicts the account's vault record freezes the vault on a fresh device | `EquivocationTest.aBranchThatContradictsTheAccountsVaultRecordFreezesTheVaultOnAFreshDevice` | pass |
| A frame whose acknowledgement was lost is re-posted byte for byte, also after a restart (T-R2) | `EquivocationTest.anEntryWhoseAcknowledgementWasLostIsRePostedByteForByteAlsoAfterARestart` | pass |
| A device never signs a second entry for a position while its first is unacknowledged (T-R2) | `EquivocationTest.aDeviceSignsNoSecondEntryForAPositionWhileItsFirstIsUnacknowledged` | pass (was H8) |
| An item head above the verified head makes the device fetch once, never freezes, marks "may be incomplete", and backs off (FS-R4, FC-10) | `EquivocationTest.anItemHeadAboveTheVerifiedHeadMakesTheDeviceFetchOnceAndThenBackOff` | pass |
| The "may be incomplete" mark goes once the verified log holds the head the item named | `EquivocationTest.anItemHintIsResolvedOnceTheVerifiedLogReachesTheHeadItNamed` | pass (was H3) |
| Reading an item whose head is above the verified head makes the host fetch the log (in the pull that decrypts it; the mark outlives a restart) | `EquivocationTest.readingAnItemWhoseHeadIsAboveTheVerifiedHeadMakesTheHostFetchTheLog` | pass (was H4) |

### Device links (§8.2, §8.3, §2.4 "Device link")

| Rule | Test | Status |
|---|---|---|
| A different `nonceE` after the reveal is `nonce_changed` and cancels, before any password (T2-R-b) | `DeviceLinkTest.aDifferentNonceEServedAfterTheRevealCancelsTheLinkBeforeAnyPassword` | pass |
| A claim that changes under the existing device (`nPub`, `name`, `platform`, `commitN`) is `claim_changed` and cancels | `DeviceLinkTest.aClaimThatChangesAfterTheExistingDeviceFixedItCancelsTheLink` | pass |
| The same swap after the digits were typed is caught at the approval; nothing is sealed | `DeviceLinkTest.aClaimSwappedAfterTheDigitsWereTypedIsCaughtAtTheApprovalAndNothingIsSealed` | pass |
| A claim altered before the existing device saw it is `bad_mac` | `DeviceLinkTest.aClaimTheServerAlteredBeforeTheExistingDeviceSawItIsBadMac` | pass |
| A reveal that does not open `commitN`, or a second one, is `bad_reveal` | `DeviceLinkTest.aRevealThatDoesNotOpenTheClaimsCommitmentOrChangesLaterIsBadReveal` | pass |
| An `outer` or `approveMac` of another link, another account, or the server's own making is `bad_mac` before any password prompt (FC-3) | `DeviceLinkTest.anOuterOrApprovalFromAnotherLinkOrOfTheServersMakingIsBadMacBeforeAnyPasswordPrompt` | pass |
| An `inner` of another link or another account is `bundle_unopenable`; the new session is signed out at once | `DeviceLinkTest.anInnerFromAnotherLinkOrAnotherAccountIsBundleUnopenableAndTheNewSessionIsSignedOut` | pass |
| A pickup answer carrying another account's session or keys is `identity_mismatch` | `DeviceLinkTest.aPickupAnswerCarryingAnotherAccountsSessionOrKeysIsIdentityMismatch` | pass |
| A chain that stays below the bundle's card checkpoint is `pin_mismatch`: signed out, and only the pin the link made is dropped | `DeviceLinkTest.aCardChainThatStaysBelowTheBundlesCheckpointIsPinMismatchSignsOutAndDropsOnlyThePinTheLinkMade` | pass |
| A second claim racing the first gets `link_claimed`; the hijacked link ends at the typed digits; no device is created | `DeviceLinkTest.aSecondClaimRacingTheFirstLosesAndTheHijackedLinkEndsAtTheTypedDigits` | pass |

### Links (§6.6 to §6.11, §2.4; T12)

| Rule | Test | Status |
|---|---|---|
| A second, different reveal fails the link for good; no code is shown or accepted (T2-R-b) | `LinkTest.aSecondDifferentRevealFailsTheLinkForGoodAndNoCodeIsShown` | pass |
| A reveal that does not open the commitment is `bad_reveal` | `LinkTest.aRevealThatDoesNotOpenTheOffersCommitmentIsBadRevealAndNoCodeExists` | pass |
| A server that lies about the creator (`reported_creator_mismatch`), the kind (`kind_mismatch`) or the offer (`unopenable`): nothing is sent or pinned | `LinkTest.aServerThatLiesAboutALinksCreatorKindOrOfferStopsTheRecipientBeforeAnythingIsSentOrPinned` | pass |
| An answer swapped for another link's (`unopenable`) or attributed to someone else (`reported_answerer_mismatch`) pins nobody | `LinkTest.anAnswerSwappedForAnotherLinksOrAttributedToSomeoneElseIsIgnoredAndNobodyIsPinned` | pass |
| Of two answers racing, the loser gets `link_used` and pins nobody | `LinkTest.ofTwoAnswersRacingForOneLinkTheLoserIsToldItIsUsedAndPinsNobody` | pass |
| An answer to a revoked link is ignored whatever the server says (T-R3) | `LinkTest.anAnswerToARevokedLinkIsIgnoredWhateverTheServerSays` | pass |
| A replayed link answer changes nothing | `LinkTest.aReplayedLinkAnswerChangesNothing` | pass |
| A link whose card the server withholds from the recipient is `card_not_in_chain` | `LinkTest.aLinkWhoseCardTheServerWithholdsFromTheRecipientIsCardNotInChain` | pass |
| A middle party relaying a link cannot make the codes match: `compared` stays false and nothing attached is shared (T-B1, T-B2) | `LinkTest.aMiddlePartyRelayingALinkCannotMakeTheCodesMatchAndNothingAttachedIsShared` | pass |

### Swapped envelopes and server-chosen values (spec 05 T1; G1, G2; §3.5, §3.6, §5.2, §5.3)

| Rule | Test | Status |
|---|---|---|
| A grant of another vault, for another member, or of an earlier `add` is refused and never becomes a prompt | `SwappedEnvelopeTest.aGrantFromAnotherVaultForAnotherAccountOrOfAnEarlierAddIsRefusedAndNeverBecomesAPrompt` | pass |
| A wrapped vault key of another vault or another account opens nothing on a fresh device (T-B3) | `SwappedEnvelopeTest.aWrappedVaultKeyOfAnotherVaultOrAnotherAccountOpensNothingOnAFreshDevice` | pass |
| An item blob or a vault name served in another slot is never shown there | `SwappedEnvelopeTest.anItemBlobOrVaultNameServedInAnotherSlotIsNeverShownThere` | pass |
| A role the server reports, or an entry a colluding member signs, never changes who owns or holds a vault (`not_authorized`) | `SwappedEnvelopeTest.aRoleTheServerReportsOrAnEntryAColludingMemberSignsNeverChangesWhoOwnsOrHoldsAVault` | pass |
| A substituted `identityPub`, a genesis of another account, instance or user, a missing or unsigned genesis, or a personal wrap the genesis does not name is the identity fault; a withheld or unopenable wrap is only "no personal vault" | `SwappedEnvelopeTest.aSubstitutedIdentityKeyGenesisOrPersonalWrapIsTheIdentityFaultAtSignIn` | pass |

### Recovery (§4.5, §9.3, §10; R27, R30)

| Rule | Test | Status |
|---|---|---|
| A recovery public key the server substitutes is never offered and nothing is sealed to it | `RecoveryTest.aRecoveryPublicKeyTheServerSubstitutesIsNeverOfferedAndNothingIsSealedToIt` | pass |
| A `recoveryFp` change without the outgoing key's signature is never followed silently: the takeover warning, also when a genuine rotation made for another instance is replayed; a new consent is warned too | `RecoveryTest.aRecoveryKeyChangeWithoutTheOutgoingKeysSignatureIsNeverFollowedSilently` | pass |
| A kit-recovery answer carrying another account's identity stops before any new password; the kit's pin is dropped | `RecoveryTest.aKitRecoveryAnswerCarryingAnotherAccountsIdentityStopsBeforeAnyNewPassword` | pass |
| An assisted-recovery answer is believed only when the pinned card's recovery key signed it for this request and identity (`unopenable`, `signer_not_pinned_key`, `request_mismatch`, `identity_mismatch`), and the person still checks the account | `RecoveryTest.anAssistedRecoveryAnswerIsBelievedOnlyWhenThePinnedRecoveryKeySignedItForThisRequestAndIdentity` | pass |

### Account state, the sync page, password-only devices (§5.4, §8.5; R20, R23, R35)

| Rule | Test | Status |
|---|---|---|
| An older or withheld account-state blob is reported, merged and never adopted; the high-water mark holds | `AccountStateTest.anOlderOrWithheldAccountStateBlobIsReportedMergedNotAdoptedAndTheHighWaterMarkHolds` | pass |
| On a password-only device the server alone can hide a contact or restore a removed one, never add one; nobody is current before the one-tap list; a tombstone held locally beats the replay | `AccountStateTest.onAPasswordOnlyDeviceTheServerAloneCanHideOrRestoreAContactButNeverAddOne` | pass |
| A contact planted by a holder of the account's key is current nowhere until the person confirms it on the device | `AccountStateTest.aContactPlantedByAHolderOfTheAccountsKeyIsCurrentNowhereUntilThePersonConfirmsItOnTheDevice` | pass |
| The account's vault record reaches the verified head once the batching interval has passed | `AccountStateTest.theAccountsVaultRecordReachesTheVerifiedHeadOnceTheBatchingIntervalHasPassed` | pass (was H5) |
| An older sync page does not make a device forget newer items; the sync answers `rev_regression` and warns (spec 05 T1) | `AccountStateTest.aSyncPageOlderThanOneTheDeviceHasSeenDoesNotMakeItForgetNewerItems` | pass (was H6) |
| An older whole snapshot served in place of a delta is a rollback | `AccountStateTest.anOlderWholeSnapshotServedInPlaceOfADeltaIsARollback` | pass |
| An older whole snapshot after a `410 resync_required` is still a rollback | `AccountStateTest.anOlderWholeSnapshotAfterAResyncDemandIsStillARollback` | **H9** |
| A second device of Bob signed in with the password only, before the accept or after it, gets the vault Bob accepted on his first device by itself (the account's answer and the self-wrap), every item in it included; the first device's self-wrap post lost once (`500`, never seen by the server) is made again after the retry interval; neither second device posts a wrap or a log entry | `SecondDeviceTest.aPasswordOnlySecondDeviceGetsTheVaultTheAccountAcceptedByItselfWhicheverItSignedInFirst` | pass (core's `SecondDeviceTest` has every order) |

### Attachments (spec 02 §6; spec 05 T1)

| Rule | Test | Status |
|---|---|---|
| Another item's attachment, another vault's, or the genuine one with half its bytes replaced, served in an attachment's place, opens to nothing (`Corrupt("content")`; all three files the same size) | `AttachmentTest.anAttachmentServedInAnotherAttachmentsPlaceOpensToNothing` | pass |
| A body far larger than the item's claim, by `Content-Length` and with no length (endless, chunked): the capped `fetchBytes` refuses it (`body_over_limit`) after the device took at most the cap | `PinRulesTest.anAttachmentBodyLargerThanItsClaimIsRefusedAtTheCapByLengthAndWithoutOne` | pass |
| The same lie through the item engine's own download: `Corrupt("size")`, holding no more than the claim | `PinRulesTest.anAttachmentBodyLargerThanItsClaimIsRefusedByTheItemEngineAtTheCap` | **H11** |

### The pin store's rules (§4.4 "No credential goes to an origin without a pin in force", "Rules for the pin store", §12.3)

| Rule | Test | Status |
|---|---|---|
| A kept session whose pin record is gone sends nothing with a credential: sync, an item write, a log append, an account-state read, a refresh, a re-authentication's prelogin and the sign-out's logout | `PinRulesTest.aKeptSessionWhosePinRecordIsGoneSendsNothingWithACredentialSignOutIncluded` | pass |
| A fork judged while the person forgets the server and pins again (a held refresh, a new card 0) marks nothing: the new pin stays in force, also after a restart | `PinRulesTest.aForkJudgedWhileThePersonForgetsTheServerAndPinsAgainLeavesTheNewPinInForce` | pass |
| A move onto the baked address by an instance that is not the baked one is refused before the pin moves; the baked address is never dialed (trust engine built with a baked instance in the test) | `PinRulesTest.aMoveOntoTheBakedAddressByAnInstanceThatIsNotTheBakedOneIsRefusedBeforeThePinMoves` | pass |
| "Forget this server" under a forked and under a damaged pin removes every record of that server and its account and nothing of another server or account, sends nothing, and the Trust Gate then works again | `PinRulesTest.forgetThisServerUnderAForkedAndADamagedPinRemovesEverythingOfThatServerAndNothingElse` | pass |

### Every answer read to its route's cap (`ResponseCaps` in core)

Each lie is told twice: a `Content-Length` far past the cap, and no length at all (chunked, 64 MiB past the cap). The device takes at most the cap plus what sockets buffer, refuses with `body_over_limit`, and its device state is what it was.

| Rule | Test | Status |
|---|---|---|
| An endless card chain before the Trust Gate: no Trust Gate, nothing pinned; the honest chain then pins | `AnswerCapsTest.anEndlessCardChainBeforeTheTrustGateIsRefusedAtItsCapAndNothingIsPinned` | pass |
| An endless client policy | `AnswerCapsTest.anEndlessPolicyIsRefusedAtItsCap` | pass |
| An endless sync (cap 256 MiB, so this one reads that much): the copy is unchanged | `AnswerCapsTest.anEndlessSyncIsRefusedAtItsCapAndTheCopyStaysAsItWas` | pass |
| An endless vault log page: the verified log is unchanged | `AnswerCapsTest.anEndlessLogPageIsRefusedAtItsCapAndTheVerifiedLogStaysAsItWas` | pass |

### A session the server ends (§4.4 "A session the server ends does not delete the device's copy"; through the CLI host)

| Rule | Test | Status |
|---|---|---|
| A device the operator revoked ends its session at the next refresh, keeps every record, and sends no bearer after | `SessionEndTest.aDeviceTheOperatorRevokedEndsItsSessionAtTheNextRefreshAndKeepsItsRecords` | pass |
| Every 401 envelope to a refresh ends the session (the five codes the server sends and an unknown one), and nothing else does: 403, 400, 429, 500, a 401 that is not the envelope, a 401 too large to read, a 200 that is not a token pair, no answer | `SessionEndTest.every401ToARefreshEndsTheSessionAndNothingElseDoes` | pass |
| A server that ends a session and then answers everything with 401 cannot make the device delete anything; the password opens it again with its items | `SessionEndTest.aServerThatEndsASessionCannotMakeTheDeviceDeleteWhatItHolds` | pass |

### The event bell's frames (spec 03 §6; `ResponseCaps.of(EVENTS)` = 64 KiB; over a real socket)

The proxy cannot upgrade a socket, so these devices are made with a `HostileBell` (`World.device(tag, bell = …)`): the
ticket is minted through the proxy by the real server, and the socket goes to the hostile bell on its own loopback port,
which registers it honestly (`pong`) and then lies. The bell under test is the engine's `EventBell` over the host's own
session client and `dialer.bellSocket(origin)`.

| Rule | Test | Status |
|---|---|---|
| A frame whose header declares 1 TiB, a frame whose fragments never end (64 MiB past the cap, 4 KiB fragments), and a whole frame of 1 MiB: the device takes at most the cap plus what sockets buffer, drops the socket, rings nothing but its registration, does not end the session; the session's tokens, the pin, the device state and the copy are unchanged, and the next sync works | `BellFrameTest.anOversizedOrEndlesslyFragmentedBellFrameDropsTheSocketAndKeepsNothing` | pass |
| A frame of exactly the cap keeps the socket (the bell skips a frame it cannot use) and an honest ring after it arrives; one byte over drops the socket before the ring that follows | `BellFrameTest.aBellFrameAtTheCapKeepsTheSocketAndOneByteOverDropsIt` | pass |

Before the fix (ktor's default session over the JVM engine, whose session ignores `maxFrameSize`), the 1 TiB frame was
reassembled in memory with no limit: the device took all 64 MiB of it and the bell stayed `OPEN`, waiting for a close
that a hostile server never sends.

| Rule | Test | Status |
|---|---|---|
| A flood of 400 honest-looking rings, each `rev` higher, sent at once: the bell hands up every ring once, in order, without waiting for a pull; the socket stays open, the newest ring is seen, and the app's handler pulls a few times, never once per ring | `BellLiesTest.aFloodOfHonestLookingRingsCostsTheDeviceAFewPullsNotOnePerRing` | pass (was H12) |
| A ring of `Long.MAX_VALUE / 2`, then an honest lower one: both handed up, the socket stays open, the absurd ring costs one pull and the honest one after it pulls again | `BellLiesTest.anAbsurdlyHighRingCostsOnePullAndAnHonestLowerRingAfterItStillPulls` | pass |

The ring handler in `BellLiesTest` is the app's own (`EngineVault.startBell` since the fix of H12), on one
thread as the app's main thread is: it never waits for the pull, rings that arrive while a pull runs cost one more pull
after it, and a ring is measured only against the rev a pull was answered at. What these two test of the device is the
bell itself; the app's handler is tested against the real glue in core (below).

The bell's other lies need the app's ring handler (`EngineVault.startBell`, `EngineAppApi.bellRevoked`), which the
headless host does not have, so they are core tests against that glue with a scripted socket
(`core/src/commonTest/.../app/engine/EngineBellLiesTest.kt`):

| Rule | Test | Status |
|---|---|---|
| Rings whose number goes backwards (5, then 3, 4 and 5 again) pull nothing after the first | `EngineBellLiesTest.aRingWhoseNumberGoesBackwardsCostsNoPull` | pass |
| A ring carrying another account's (far higher) number costs at most one pull and never stops later honest rings from pulling | `EngineBellLiesTest.aRingWithAnotherAccountsNumberNeverStopsLaterRingsFromPulling` | pass (was B1) |
| A `revoked` frame for a device that is not revoked ends the session as the server's end, and that end keeps the copy: no cache file deleted, no logout sent, nothing sealed sent, the session kept marked as ended by the server | `EngineBellLiesTest.aRevokedFrameForADeviceThatIsNotRevokedEndsTheSessionAndKeepsTheCopy` | pass |

### A vault taken away, and the holding area (spec 02 §10.6; spec 03 §4 `removedGrants`, amended 2026-11-15)

| Rule | Test | Status |
|---|---|---|
| An edit the server denies while taking the vault away is held back (vault read-only, not gone) and sent when the vault comes back | `HoldingTest.anEditTheServerDeniesWhileTakingTheVaultAwayIsHeldBackAndSentWhenTheVaultComesBack` | **H10** |
| A departed vault is held 30 days from when the device saw the departure, whatever purge time the server names | `HoldingTest.aDepartedVaultIsHeldThirtyDaysFromWhenTheDeviceSawItWhateverPurgeTimeTheServerNames` | pass |

### Lies with no scenario before (the table below); `LyingAnswersTest`

| Rule | Test | Status |
|---|---|---|
| A prelogin that weakens the KDF (memory or passes below the floor), inflates it past the ceiling, serves a salt of 8 bytes or not base64, another algorithm, the client policy's answer, half an answer (by length and chunked), a plain `ok`, or a redirect: no login, no `authKey` in any request, the password wiped, never "wrong password", nothing kept; the honest prelogin then signs in | `LyingAnswersTest.aPreloginThatWeakensTheKdfOrIsNotAPreloginGetsNoPasswordProof` | pass |
| Half an answer, by its length and chunked, to a sync, a log page, the card chain and the account state: the device's records, items, log status, account state and pin are what they were; the next sync works | `LyingAnswersTest.aTruncatedAnswerChangesNothingAndIsNeverReadAsNothingThere` | pass |
| A valid answer made for another route: a sync answered with a log page or the account state, a log page with another vault's log, the card chain with a sync page, the account state with the usage ledger's answer: nothing the device holds changes, except that the other vault's log is a failure (§3.9: warned, writes refused, verified state kept) that ends at the next honest fetch | `LyingAnswersTest.anAnswerMadeForAnotherRouteChangesNothing` | pass |

### Redirects (spec 03 §0.1 "Redirects"); `RedirectTest`

No route of the protocol answers with a redirect, so the engine's `Dialer` follows none (its client is the host's with
`followRedirects = false`; `DialerRedirectTest` in core covers every `3xx`, https to http, and IP literals).

| Rule | Test | Status |
|---|---|---|
| A sync (with its bearer), the card chain before the Trust Gate and the client policy (no credential), each answered `302` to another path on the origin, another host, another host name over plain http, or `127.0.0.2` (an address no origin may name, watched by a socket of the test's own): nothing is followed or dialled, the device holds what it held, a sync is not a sync, no Trust Gate is shown, nothing is pinned; the honest answers then work | `RedirectTest.aRedirectIsNeverFollowed_withACredentialOrWithout` | pass (was a finding) |

Before the fix (ktor's default `HttpRedirect`), every one of the twelve was followed: on the origin with the bearer
(the sync) or without (the card chain, the policy); to the other host and to the plain-http host name, with the bearer
dropped (ktor strips `Authorization` across hosts) but the request sent; and `127.0.0.2` was dialled for all three.

### Lies about key material (spec 05 T1; §2.4 "Account keys at sign-in, unlock, kit recovery and device-link pickup"); `KeyMaterialTest`

Each lie is a replay of an earlier honest exchange (the same account before its password or kit changed), another
account's valid answer, or the right answer with one field taken from another's or an earlier one. Where a lie is
taken, the test also checks that the keys the device keeps for its next unlock still open with the person's password.

| Rule | Test | Status |
|---|---|---|
| Sign-in, and its code step: Bob's login answer, Alice's own from before her password change, the right answer with her old salt, Bob's salt, other KDF parameters, Bob's user id, or her old wrapped key: never signed in, no session, nothing kept, no device row, never "wrong password"; the honest sign-in works | `KeyMaterialTest.aSignInAnswerReplayedOrOfAnotherAccountOrWithOneFieldSwappedIsNeverTaken` | pass (was finding K1) |
| The account's keys as the command-line tool's kept session reads them: Bob's keys, Alice's from before the change, hers with Bob's salt, identity key or seed: never reopened, "sign in afresh" or the security fault, the kept session not deleted | `KeyMaterialTest.theAccountsKeysReplayedOrOfAnotherAccountOrWithOneFieldSwappedNeverReopenASession` | pass |
| The kit's verify: Bob's answer, Alice's own from before her kit was rotated, the right one with Bob's user id: `identity_mismatch` before any new password, never "wrong kit", nothing committed | `KeyMaterialTest.aKitVerifyAnswerReplayedOrOfAnotherAccountStopsBeforeAnyNewPassword` | pass |
| The kit's commit (landed on the server): Bob's session, Alice's own from before the recovery, the right one with Bob's salt or her old wrapped key: never the recovered session, never "wrong kit"; the new password then signs in | `KeyMaterialTest.aKitCommitAnswerReplayedOrOfAnotherAccountOrWithOneFieldSwappedIsNeverTheRecoveredSession` | pass (was finding K2) |
| A device link: the earlier link's approved poll answer stops before any password; the earlier link's whole pickup answer, its session in this link's answer, or this link's answer with the salt from before the password change or other KDF parameters: `identity_mismatch`, no session, no device row | `KeyMaterialTest.aDeviceLinkPollOrPickupAnswerReplayedOrWithOneFieldSwappedIsNeverTaken` | pass (was finding K3) |

K1 to K3 were one defect: the session's `accountKeys` were taken from the answer with their `kdfSalt`, `kdfParams` (and,
at a commit, `wrappedUvk`) never compared with what the device itself derived under or sent, so the keys a device kept
for its next unlock were not the ones the person's password opens, and the next unlock said "wrong password". Now
`SessionOpener` (sign-in, registration, the kit and assisted commits) and the device link's pickup refuse such an
answer (`bad_response`; the pickup's `identity_mismatch`, signing the new session out).

### The vault log's answers replayed or reordered (§3.7, §3.9; spec 03 §10.3); `LogReplayTest`

| Rule | Test | Status |
|---|---|---|
| A log append answered with an earlier append's answer (not stored), another vault's answer, the right answer with an earlier head, and two appends in two vaults each answered with the other's: the replay leaves the append pending and the verified state where it was, and the re-post lands it; each stored append is the newest verified state; nothing goes back | `LogReplayTest.aReplayedOrReorderedLogAppendAnswerNeverMovesTheVerifiedStateBack` | pass |
| After Bob is made a reader and Carol removed, each device served the log from before (Carol also her old grant and vault rows): Bob is still a reader, Carol still removed, neither writes, the owner's device shows neither change undone; the older page is withholding, and the honest log clears it | `LogReplayTest.aLogPageReplayedFromBeforeARemovalOrARoleChangeNeverShowsTheOldMembership` | pass |

A fresh device of Bob's that never verified the demotion cannot tell an older page from the truth beyond the account's
own vault record (`WithholdingTest`), which is written in batches; the server refuses the writes of a reader anyway.

### The devices list in pages (spec 03 §16.7; index rows 26 and 77); `DevicePagesTest`

The engine reads every page (`?after=<last deviceId>` while a page holds 500 rows) and answers the list only when its
last page arrived (`DevicePages` in core: at most 40 pages; a repeated device, more than 500 rows, a cursor that is
not a uuid, or two devices marked `current` is `bad_page`; any refused page fails the whole read).

| Rule | Test | Status |
|---|---|---|
| Every page full of new devices, in the account's own view and the operator's view of it: the device asks for exactly 40 pages, each with the last device of the page before as its cursor, shows no list (`too_many_pages`), and the honest list then reads | `DevicePagesTest.aDevicesPageThatNeverEndsStopsAtTheStatedNumberOfPagesAndShowsNoList` | pass |
| The real first page (made full) served again for the cursor, or a second page that brings back one device of the first: no list (`bad_page`), in both views, after two requests | `DevicePagesTest.aCursorThatLoopsFailsTheWholeRead` | pass |
| Alice's first page and then Bob's own devices list as he was served it, or Bob's whole list as hers: no list (two current devices; with the reader bound to the session's device id, a current device that is not this one). The operator's view: a page of another account carries no mark and is taken (the limit, stated) | `DevicePagesTest.aPageOfAnotherAccountIsNeverShownAsTheAccountsOwnDevices` | pass |
| The host's own reader (`Host.settings`) reads Alice's own list (exactly her device `current`) and refuses Bob's whole list served as hers | `DevicePagesTest.theHostsOwnDevicesReaderRefusesAnotherAccountsWholeList` | pass (was D1) |

### The deleted-items list in pages (spec 03 §5.1; index row 39); `TrashPagesTest`

The engine reads every page (`?after=<deletedAt>:<itemId>` of the last row while a page holds 65,536 rows) and has a
trash only when its last page arrived (`ItemEngine.trashRows` in core: at most 16 pages; a page of more than 65,536
rows, rows not strictly descending in `(deletedAt, itemId)`, a first row not strictly after the cursor, or a full page
whose last row names no next row is `trash_incomplete`; any refused page fails the whole read; a row of a vault the
account may not read is left out).

| Rule | Test | Status |
|---|---|---|
| The real first page (made full) served again for the cursor, a second page that starts above the cursor, or one that brings back a row of the first: no trash (`trash_incomplete`) after two requests; nothing restored or purged; the honest trash then reads | `TrashPagesTest.aTrashPageThatLoopsFailsTheWholeRead` | pass |
| Every page full of new rows, each below the one before: exactly 16 requests, each after the last row of the page before, no trash; a page of 65,537 rows is refused at once; the honest trash then reads | `TrashPagesTest.aTrashListThatNeverEndsStopsAtTheStatedNumberOfPages` | pass |
| Bob's own deleted items served as Alice's page, whole or mixed into hers in order: none of Bob's rows is in her trash, all of hers are | `TrashPagesTest.aTrashPageOfAnotherAccountsRowsIsNeverShownAsTheAccountsOwn` | pass |

### Registration and the assisted recovery's commit (the last row, in the order of what a lie could cost); `RegistrationLiesTest`, `AssistedCommitLiesTest`

| Rule | Test | Status |
|---|---|---|
| A register answer (after the server created the account) replaced by Bob's whole answer, or the right answer with Bob's user id, salt, wrapped key or identity key, or a plain `ok`, or an empty object: never registered on the device, never a password verdict, no session kept; the account the server created then signs in with the password from a fresh device | `RegistrationLiesTest.aRegisterAnswerOfAnotherAccountOrWithOneFieldSwappedOrNotARegisterAnswerIsNeverTaken` | pass |
| The assisted recovery's commit (after a genuine answer signed by the offline key and the person's "this is my account") answered with Bob's session or with Alice's own session from before the recovery: never the recovered session, never a password verdict, no session kept, the commit sent once; Alice's password still signs in | `AssistedCommitLiesTest.anAssistedCommitAnswerOfAnotherAccountOrFromBeforeTheRecoveryIsNeverTheRecoveredSession` | pass |

### The recovery routes of the last row, most dangerous first; `RecoveryRouteLiesTest`

| Rule | Test | Status |
|---|---|---|
| `POST /recovery/requests` answered (not passed on) with an id that is not one, `ok` or `{}`: the flow stops, nothing is kept, nothing more is sent. Passed on and answered with Bob's live request id or Alice's own earlier one: shown as requested (the device cannot tell), but the code from Alice's email is `bad_code` there, the step never becomes a hold, a poll is never "check the account", and no hold begins for any request of Alice's | `RecoveryRouteLiesTest.aRequestCreateAnswerThatIsNotThisRequestsIdNeverLeadsPastTheEmailedCode` | pass |
| The request's verify answered (not passed on) with `{}` or `ok`: unreachable, the step kept, and the honest code then starts the real hold. With a hold that ended long ago (`-1`) or `ready` and a hold that never ends: shown as `holding` with the server's hold (its word, R27), nothing else sent, and the next poll is never "check the account" without the operator's signed answer | `RecoveryRouteLiesTest.aRequestVerifyAnswerThatLiesAboutTheHoldNeverLeadsPastWaiting` | pass |
| `PUT /account/recovery`, after the server stored the change, answered with Bob's answer, Alice's earlier one, its `seq` a million ahead or `-1`, `{}` or `ok`: done or unknown (never "wrong password"); the posture the server then shows is the person's choice; the next change from the same device is done (a lied `seq` costs at most a `stale_state` round) | `RecoveryRouteLiesTest.aRecoveryChoiceAnswerOfAnotherAccountOrAnEarlierOneLeavesTheChoiceAndTheNextChangeWorks` | pass |
| `PUT /recovery/self-setup` (a new kit), after the server stored it, answered with Bob's piece id or Alice's earlier one: the kit is revealed with that id (it only binds "I saved it") and recovers Alice's account on a fresh device; an id that is not one or `{}`: unknown, and the next rotation's kit recovers the account | `RecoveryRouteLiesTest.aKitRotationAnswerOfAnotherPieceStillRevealsAKitThatRecoversTheAccount` | pass |
| `GET /account/recovery-requests` (the live requests a signed-in device can stop): a row with an id, platform or state that is not one is dropped and counted (`Listed.unreadable`), never the whole list; `{}` or `ok` is unreachable, never "no requests"; Bob's list as Alice's, or hers from before her veto, is shown (a row names no account: the stated limit), and her veto of such a row cancels nothing; Bob's request lives on | `RecoveryRouteLiesTest.aLiveRequestsListThatIsNotThisAccountsOwnNeverCancelsAnything` | pass |
| The same list after the operator's upload: the real server lists the request as `ready`, the account's device lists it with the others and cancels it, and its requester is told `vetoed`. Over the honest body, a row in a state the specification does not name, one whose id is not one, or one that is not an object (W): that row dropped and counted, the others kept; every row unreadable: an empty list that says how many were dropped; a body that is not a list (X): no answer | `RecoveryRequestListLiesTest.anAnsweredRequestIsListedAndCancelledAndOneUnreadableRowNeverEmptiesTheList` | pass |
| The server's recovery key changes while a fresh install's request is open: the operator stores the rotation signed offline by the outgoing seed, then the card naming the new key. Served honestly, the request goes on and the device says that the key changed and when (the statement's own signed time). Served with no rotation, with one byte of the statement's signature changed, or with the same statement signed by the new key alone (`GET /instance`, W): the request stops with spec 04 §5's warning, nothing is polled (so nothing of an answer is fetched or opened), and it is kept | `RecoveryKeyChangeLiesTest.aRecoveryKeyRotatedWhileARequestIsOpenIsFollowedOnlyThroughARotationTheDeviceVerifies` | pass |
| The poll of an answered request: `ready` naming a commit hash that is not the stored answer's (W): "the answer on the server is not the one this device opened" before the person is asked anything, the request kept, nothing more sent; the stored answer's own hash, or no such field (a server from before it): on to the account check and the commit. `404 request_unknown` to the poll of a live request (X): said as such, the request kept, and the next honest poll goes on | `ReadyAnswerLiesTest.aReadyAnswerNamingAnotherCommitHashOrA404IsSaidAndTheRequestKept` | pass |
| The operator's upload and the commit (a scenario from another part of the build, counted here): "done" to an upload the server never stored (`…/fulfil`, W: the list it reads next still says awaiting, the device still waits); the person's answer served for another request's poll (A: `unopenable`, nothing committed); a commit whose value the server takes away (`…/commit`, W: `bad_commit`, the request kept, and the person finishes once the server stops lying) | `AssistedUploadLiesTest.anUploadTheServerDidNotStore_anAnswerUnderAnotherRequest_andACommitWithoutItsValue` | pass |
| The operator's escrow route: Bob's whole answer, or Alice's with Bob's user id, is `bad_response`; `{}` and `ok` are never a done escrow; Alice's user id with Bob's sealed escrow, seed and identity key is taken (the stated limit: the device cannot open an escrow sealed to the offline key; `recovery-cli` checks it against the request's user and identity fingerprint, `EscrowVerifyTest`) | `RecoveryRouteLiesTest.anEscrowAnswerOfAnotherAccountIsRefusedOnTheOperatorsDevice` | pass |

Two limits these state, not findings: a lied piece id makes the kit's later "I saved it" confirmation answer
`recovery_piece_stale` for a kit that is in fact current (the person is asked to save a new one: liveness only), and
a lied hold time is shown as the server's word.

### The account's own use and limits (spec 03 §14.4, "What an account is told"; index rows 36 and 73); `QuotaLiesTest`

The device does what every app does before a large copy: a fresh sync and core's shared check (`ItemEngine.roomFor`,
`QuotaCheck`); short, and nothing starts; room or unknown, and the import goes to the server, whose own check decides.
The honest limit in these worlds is 5 items.

| Rule | Test | Status |
|---|---|---|
| `quota` on every `/sync` answer replaced by limits of zero, a use larger than any limit, use and limit both at the top of a `Long`, negative numbers, numbers past a `Long` (with a fraction and a word), a limit at the top of a `Long` with nothing used, and another account's (Bob's) object: the sync succeeds and the items shown stay as they were in every case; a short answer sends nothing; a negative or absurd number is "unknown" (the device holds no meters), never room; an unknown or roomy answer lets the import reach the server, which takes exactly what fits and refuses the rest `quota_exceeded`. The server ends at the honest limit, not one item more, and the device then shows exactly that | `QuotaLiesTest.aServerThatLiesInTheMetersOnlyMakesTheDeviceRefuseEarlyOrMeetTheServersRefusal` | pass |
| `GET /admin/accounts` with a row's `quota` replaced by negative numbers, numbers past a `Long`, something that is not an object (unknown, null, each), or Bob's object in Alice's row (shown: a row's `quota` names no account, as its `usedBytes` does not; it decides nothing): the list reads every time, every other field as served, and nothing but reads is sent | `QuotaLiesTest.anAccountsListWhoseMetersLieStillReadsAndAnAbsurdMeterIsUnknown` | pass |


### The create answers, the self-wrap and an item's versions (the last row, most dangerous first); `CreateAnswerLiesTest`

Each lie replaces the answer after the real server acted on the request.

| Rule | Test | Status |
|---|---|---|
| `POST /device-links` answered with `ttlMs` at -1, at the top of a `Long` or ten days (W), Bob's answer (A), Alice's earlier one (R): the link shown is the device's own, a new device's claim goes to the link the device asked for, and the device that made it sees the claim; `{}` and `ok` (X) show no link | `CreateAnswerLiesTest.aDeviceLinkCreateAnswerThatLiesNeverChangesWhichLinkIsShown` | pass |
| The countdown of a device link or a link is never below 0 nor longer than the lifetime the device asked for, whatever `ttlMs` says | `CreateAnswerLiesTest.aCreateAnswersCountdownIsNeverNegativeNorLongerThanAsked` | pass (was L1: bounded in `WireDeviceLinks.create` and `WireLinkFlows.create`) |
| `POST /links` answered with `ttlMs` -1 (W), Bob's answer (A), Alice's earlier one (R), `{}` or `ok` (X): whatever the device keeps is its own link id and URL, and Carol opening it is shown Alice's offer | `CreateAnswerLiesTest.aLinkCreateAnswerThatLiesNeverChangesWhichLinkIsShared` | pass |
| `PUT /vaults/{id}/grant/self-wrap` answered, after the server stored it, with a rev a million ahead or -1 (W), `{}`, `ok` or a `500` (X): Bob reads the vault he accepted and Alice's writes in it, and the server holds on Bob's grant of each exactly the self-wrap he posted | `CreateAnswerLiesTest.aSelfWrapAnswerThatLiesDecidesNothing` | pass |
| `GET /items/{id}/versions` answered with another item's versions (W) or Bob's item's (A): none of it is shown; with its own earlier answer (R): this item's own versions, fewer (the stated limit); `{}` and `ok` (X): a failure, never "no history" | `CreateAnswerLiesTest.anItemsVersionsAnswerOfAnotherItemOrAccountShowsNothingOfIt` | pass |

### The operator's lists as the headless host reads them (design §9.2, §9.3; index rows 77, 80, 82 to 84); `OperatorListLiesTest`

What the operator is shown is its own server speaking (§9.2: transparency for an honest operator, not a control
against a hostile one), so the property is that a lie decides nothing: only reads are sent, a shape the route never
gives is a failure and never an empty list, and the one check the design puts on the operator's side (`recovery-cli
assist` comparing the request code the person reads out with the one it computes from `rPub`, §9.3 step 3) refuses
any key the server swapped in. The upload of an answer (`…/fulfil`) is left to the round after its format changes.

| Rule | Test | Status |
|---|---|---|
| `GET /admin/recovery-requests` with Alice's row given Bob's request key or a fresh one (W), a request code added to every row (W), the answer from before Bob's request (R: withheld, the stated limit), `{}`, `ok`, a `500` (X): shown as served, but no row ever carries a request code (T2-R-c), a swapped key fails the code Alice's app shows her, a shape never given is a failure, nothing but reads is sent and no fulfilment | `OperatorListLiesTest.aRecoveryRequestListThatLiesNeverCarriesACodeAndAKeyItSwappedFailsTheOperatorsCheck` | pass |
| An account's devices answered with Bob's real list for Alice (A: rows name no account, the stated limit), `{}`, `ok`, `500` (X); the audit with its earlier answer (R) and those shapes; status with the instance's kind turned to `public` and absurd counts (W: shown as served, the recovery routes still follow the pinned card); policy with weaker values (W) and those shapes: nothing but reads, every shape never given a failure | `OperatorListLiesTest.anOperatorViewThatLiesDecidesNothingAndAShapeNeverGivenIsAFailure` | pass |
| All six reads (accounts, an account's devices, policy, audit, status, recovery requests) answered with half their answer, by length and chunked (T), with another of these routes' real answer or one accounts row (O: an object for a list, other rows for a list, a list for an object), and with an endless body by a lying length and with none (S): each is a failure (T, O: unreachable; S: `body_over_limit`, the device taking no more than the cap and what sockets buffer), never an empty list or a view. The accounts list, status and policy from before a change (R) are shown as served (the stated limit); the accounts list's `{}`, `ok` and `500` (X) are failures. Nothing but reads is sent | `OperatorListLiesTest.anOperatorListCutShortEndlessOrMadeForAnotherRouteIsAFailure` | pass |
| A self-contradicting list (a request twice or with an id outside its grammar, an audit row twice, 501 audit rows, rows outside the filter asked, a device marked `current`) is refused whole, as the app's console refuses it | `OperatorListLiesTest.aSelfContradictingOperatorListIsRefusedAsTheConsoleRefusesIt` | **O1** |

### The account state written (spec 03 §3, design §5.4; the last row); `AccountStateWriteLiesTest`

| Rule | Test | Status |
|---|---|---|
| `PUT /account/state`, stored by the server, then answered with the compare-and-set token far below or far above the true one or the blob altered (W), Bob's answer (A) or Alice's earlier answer (R): the document the device holds is exactly the one it wrote (it keeps only the token from an answer, never its blob), nothing of Bob's, and the next honest write lands with every change so far. Not stored and answered `ok`, `{}` or a `500` (X): never reported written, nothing earlier lost, and the next honest write carries the change. `409 stale_state` to every attempt: `Contended` after a bounded number of attempts | `AccountStateWriteLiesTest.aWriteAnswerThatLiesNeverReplacesTheDocumentAndTheNextWriteLandsWithEverything` | pass |

### Recently deleted vaults and the restore of an item (spec 03 §11.2, §5.1; the last row); `DeletedVaultRestoreLiesTest`

| Rule | Test | Status |
|---|---|---|
| `GET /vaults/deleted` with a row whose id is not a UUID, or whose purge comes before its deletion (dropped), a row twice (shown once), the sealed name altered (shown without a name), a live vault served as deleted (shown unverified: the log has no `delete`) (W); Bob's deleted vault, of which Alice was never a member (A: no name, since the name is opened only with a key the device holds, and unverified); the list from before the delete (R: withheld, the stated limit); half the answer (T), one row or another route's object (O), an endless body (S, at the cap), `{}`, `ok`, `500` (X): failures, never "nothing deleted". Only reads are sent | `DeletedVaultRestoreLiesTest.aDeletedVaultsListThatLiesNamesNothingItCannotOpenAndAShapeNeverGivenIsAFailure` | pass |
| `POST /items/{id}/restore`, stored, then answered with a revision far below or far above (W) or an earlier restore's answer (R): the item is back and stays back after the next sync (no revision is taken from the answer). Not stored and answered `ok`, `{}` or a `500` (X): a failure, the item stays in the trash, and the next honest restore brings it back | `DeletedVaultRestoreLiesTest.aRestoreAnswerThatLiesBringsBackNothingTheServerDidNotStoreAndIsNeverAWrongRevision` | pass |
| `POST /items/{id}/restore` NOT stored and answered as done with a plausible revision (W, not passed on): the restore is reported done (the device cannot tell at once); the next sync takes the server's state, so the item is not shown in the vault and is in the trash list again, and an honest restore then brings it back. Nothing says that the first restore did not happen: the stated limit below | `DeletedVaultRestoreLiesTest.aRestoreAnsweredAsDoneThatTheServerNeverStoredIsUndoneByTheNextSyncAndTheItemIsInTheTrashAgain` | pass |
| `POST /items/{id}/purge` ("delete forever"), stored, then answered with a revision far below or far above (W) or an earlier purge's answer (R): done, the item gone from the trash. Not stored and answered `ok`, `{}` or a `500` (X): a failure, the item still in the trash. Not stored and answered as done with a revision (W): reported done; the trash list read next still shows the item, and an honest purge deletes it | `DeletedVaultRestoreLiesTest.aPurgeAnswerThatLiesNeverHidesAnItemTheServerStillKeeps` | pass |

The stated limit: a restore or a purge the server answers as done and never performs is reported done, and only the
next read of the vault or the trash shows the truth. The item engine (the vault-content code's `ItemEngine.restoreDeleted`
and `purgeDeleted`) has no notice that says "the restore did not happen"; it would need one that compares the trash
list read after the action with the action.

### A shared vault's rename (spec 03 §11.3; the last row, the most dangerous left); `VaultMetaLiesTest`

| Rule | Test | Status |
|---|---|---|
| `PUT /vaults/{id}/meta`, stored, then answered with a revision far below, far above or negative (W) or an earlier rename's answer (R): done, and after the next sync both members are shown the new name (no revision is taken from the answer). Not stored and answered `ok`, `{}` or a `500` (X): a failure, both shown the name the server holds. Not stored and answered as done (W): reported done, the next sync shows the name the server holds (the stated limit, as for the restore). `409 stale_meta` to every attempt: one sync and one retry, then a failure. The next honest rename lands | `VaultMetaLiesTest.aRenameAnswerThatLiesNeverShowsANameTheServerDoesNotHold` | pass |

### The operator's card change (spec 03 §17.2; design §4.3, §4.4; the last row); `InstanceCardLiesTest`

| Rule | Test | Status |
|---|---|---|
| `PUT /instance/card` through the shared code's own path (`WireOperatorCards`), stored, then answered with a seq far above or another card's hash (W) or an earlier upload's answer (R): refused as `card_mismatch`, and the operator's device and a member's pin the stored card through the chain the server serves. Not stored and answered `ok`, `{}` or a `500` (X): never "changed" nor "stored", and no pin moves. Not stored and answered as done with the seq and hash of the very card signed (W): "stored, not yet served" at most, never "changed", and no pin moves (the stated limit). The next honest change lands on every device | `InstanceCardLiesTest.aCardUploadAnswerThatLiesNeverMovesAPinPastTheChainTheServerServes` | pass |

### Another instance's real answers (two real servers side by side, `World.another`; spec 03 §17.2, design §9.2); `OtherInstanceLiesTest`

A second instance runs beside the scenario's own, with its own server, proxy and operator; a rule serves an answer its
operator really got (`World.realAnswer`) for the same route on the first instance. Nothing in these answers is a forgery:
each is a real server's real word, about the wrong instance.

| Rule | Test | Status |
|---|---|---|
| `PUT /instance/card` answered with the other instance's real answer to its own card change (A), after the server stored this card or without passing it on: refused as `card_mismatch`, never "changed" nor "stored"; the operator's device and a member's pin only the chain this server serves (the stored card, or the one held before) | `OtherInstanceLiesTest.anotherInstancesCardUploadAnswerIsAMismatchAndMovesNoPin` | pass |
| `GET /admin/recovery-requests`, `/admin/audit`, `/admin/status` and `/admin/policy` answered with the other instance's real answers (A): each shown as served (nothing in these answers names the instance, so the device cannot tell: the stated limit, as for W, design §9.2), and none decides anything: only reads are sent, the pinned card still says the instance offers operator recovery, and no request row of the other instance passes the request code this instance's member reads out, so `recovery-cli assist` refuses to answer it | `OtherInstanceLiesTest.anotherInstancesOperatorViewsAreShownAsServedAndDecideNothing` | pass |
| `POST /signup/verify` answered with another public instance's real answer to its own sign-up (A), never passed on: the ticket is taken as served (an opaque value that names neither the instance nor the address: the stated limit), the registration with it is refused by this server, no account is made here or at the other instance, the registration went to this server alone, and nothing reached the other; the same code, still unused here, then signs the person up, and the other's ticket still signs its own person up there | `OtherInstanceSignupLiesTest.anotherInstancesSignupTicketIsTakenAsServedAndMakesNoAccountAnywhere` | `new` pass |

### The account state's counter on the sync answer (spec 03 §4 `accountStateSeq`); `AccountStateCounterLiesTest`

| Rule | Test | Status |
|---|---|---|
| A password-only second device waiting for the account's answer to an invitation: the honest counter standing still costs no read of `GET /account/state`; a counter far above or below the one the device last saw (W) is read at that round, never skipped, and adopts nothing; held still over a write of the first device (W), the answer is withheld (as serving the older state would withhold it: the stated limit) and nothing is adopted; once the counter moves, one read and the vault is adopted | `AccountStateCounterLiesTest.aCounterThatLiesInEitherDirectionCostsReadsOrWithholdsAnAnswerAndNeverForgesOne` | off: needs the sync to tell the vault-log engine the counter (`VaultLogEngine.accountStateServed`, a line in the vault-content code's `SessionVaultKeys.served`); core's `SecondDeviceTest` has the same rules at the engine's level, on |

### The usage ledger (spec 02 §8.2, spec 03 §3; index row 24); `UsageLedgerLiesTest`

| Rule | Test | Status |
|---|---|---|
| `GET /usage` answered with the blob altered (W), Bob's real blob (A), `{}`, `ok` or a `500` (X), each with a use buffered: no `PUT` follows ("could not GET or open: MUST NOT PUT"), the use stays buffered, and the next honest round writes it beside every earlier entry. Alice's earlier blob (R) and `null` for a ledger that exists (W, withheld) are written over: the device cannot tell them from the truth, and the server, which stores the blob, could drop or roll it back itself (the stated limit) | `UsageLedgerLiesTest.aUsageAnswerThatCannotBeReadOrOpenedIsNeverWrittenOver` | pass |

## What each route is lied to with

The kinds of lie: **W** a wrong body (a field changed, a row withheld or added, a forged frame); **A** another
account's, vault's, link's or instance's valid data; **R** a replay of an old valid answer; **T** a truncated answer;
**O** a valid answer made for another route; **S** an answer that never ends, or is past its cap; **X** a status or
shape the route never gives (a refusal it never sends, `ok` for a JSON route, a redirect, no answer at all). A cell
names the test class that tells that lie on that route; marks the ones this table's round added; `·` is a gap.
Rows are the routes whose answer the engine reads and acts on through the headless host, and the event bell.

| Route | W | A | R | T | O | S | X |
|---|---|---|---|---|---|---|---|
| `GET /instance` (card chain and rotations) | CardFork, Withholding, Recovery, PinRules, RecoveryKeyChangeLies | CardFork | Withholding | Lying | Lying | AnswerCaps | Redirect |
| `GET /recovery-pubkey` | Recovery | · | · | · | · | · | · |
| `GET /client-policy` | · | · | · | · | · | AnswerCaps | Redirect |
| `POST /auth/prelogin` | Lying | · | · | Lying | Lying | · | Lying |
| `POST /auth/login` (and its code step) | SwappedEnvelope, KeyMaterial | KeyMaterial | KeyMaterial | · | · | · | · |
| `POST /auth/refresh` | SessionEnd | · | · | · | · | · | SessionEnd |
| `GET /account/keys` (the command-line tool's reopen) | KeyMaterial | KeyMaterial | KeyMaterial | · | · | · | SessionEnd |
| `GET /account/state` | AccountState | AccountState | AccountState | Lying | Lying | · | · |
| `GET /sync` | SwappedEnvelope, Holding, AccountState, QuotaLies | SwappedEnvelope, QuotaLies | AccountState | Lying | Lying | AnswerCaps | AccountState (`410`), Redirect |
| `POST /sync/push` | Holding | · | · | · | · | · | Holding |
| `GET /vaults/{id}/log` | Withholding, Equivocation, SwappedEnvelope | Equivocation, Lying | Withholding, Equivocation, LogReplay | Lying | · | AnswerCaps | · |
| `POST /vaults/{id}/log` | Equivocation, LogReplay | LogReplay | LogReplay | · | · | · | Equivocation |
| `GET /links/{id}` | Link | Link | · | · | · | · | · |
| `GET /links/answers` | Link, Withholding | Link | Link | · | · | · | · |
| `POST /links/{id}/answer`, `DELETE /links/{id}` | Link | · | · | · | · | · | Link |
| `GET /device-links/{id}` | DeviceLink | DeviceLink | · | · | · | · | · |
| `POST /device-links/{id}/poll` | DeviceLink | DeviceLink | KeyMaterial | · | · | · | · |
| `POST /device-links/{id}/pickup` | DeviceLink, KeyMaterial | DeviceLink | KeyMaterial | · | · | · | · |
| `POST /recovery/self/verify` | Recovery, KeyMaterial | KeyMaterial | KeyMaterial | · | · | · | · |
| `POST /recovery/self/commit` | KeyMaterial | KeyMaterial | KeyMaterial | · | · | · | · |
| `POST /recovery/requests/{id}/poll` | Recovery, ReadyAnswerLies | AssistedUploadLies | · | · | · | · | ReadyAnswerLies |
| `POST /recovery/requests/{id}/commit` | AssistedUploadLies | AssistedCommitLies | AssistedCommitLies | · | · | · | · |
| `POST /admin/recovery-requests/{id}/fulfil` | AssistedUploadLies | · | · | · | · | · | · |
| `POST /auth/register` | RegistrationLies | RegistrationLies | · | · | · | · | RegistrationLies |
| `GET /attachments/{id}` | Attachment | · | · | · | · | PinRules | · |
| `GET /account/delete/preview` | Deletion | · | · | · | · | · | · |
| `GET /account/devices` | DevicePages | DevicePages | DevicePages | · | · | DevicePages | · |
| `GET /admin/accounts/{id}/devices` | DevicePages | OperatorListLies | DevicePages | OperatorListLies | OperatorListLies | DevicePages | OperatorListLies |
| `POST /recovery/requests` | RecoveryRouteLies | RecoveryRouteLies | RecoveryRouteLies | · | · | · | RecoveryRouteLies |
| `POST /recovery/requests/{id}/verify` | RecoveryRouteLies | · | · | · | · | · | RecoveryRouteLies |
| `PUT /account/recovery` | RecoveryRouteLies | RecoveryRouteLies | RecoveryRouteLies | · | · | · | RecoveryRouteLies |
| `PUT /recovery/self-setup` | RecoveryRouteLies | RecoveryRouteLies | RecoveryRouteLies | · | · | · | RecoveryRouteLies |
| `GET /account/recovery-requests` | RecoveryRouteLies, RecoveryRequestListLies | RecoveryRouteLies | RecoveryRouteLies | · | · | · | RecoveryRouteLies, RecoveryRequestListLies |
| `POST /admin/accounts/{id}/escrow` | RecoveryRouteLies | RecoveryRouteLies | · | · | · | · | RecoveryRouteLies |
| `GET /items/deleted` | TrashPages | TrashPages | TrashPages | · | · | TrashPages | · |
| `GET /admin/accounts` | QuotaLies | QuotaLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies |
| `POST /device-links` | CreateAnswerLies | CreateAnswerLies | CreateAnswerLies | · | · | · | CreateAnswerLies |
| `POST /links` | CreateAnswerLies | CreateAnswerLies | CreateAnswerLies | · | · | · | CreateAnswerLies |
| `PUT /vaults/{id}/grant/self-wrap` | CreateAnswerLies | · | · | · | · | · | CreateAnswerLies, SecondDevice |
| `GET /items/{id}/versions` | CreateAnswerLies | CreateAnswerLies | CreateAnswerLies | · | · | · | CreateAnswerLies |
| `GET /admin/recovery-requests` | OperatorListLies (O1) | OtherInstanceLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies |
| `GET /admin/audit` | OperatorListLies (O1) | OtherInstanceLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies |
| `GET /admin/status` | OperatorListLies | OtherInstanceLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies |
| `GET /admin/policy` | OperatorListLies | OtherInstanceLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies | OperatorListLies |
| `GET /usage` | UsageLedgerLies | UsageLedgerLies | UsageLedgerLies | · | · | · | UsageLedgerLies |
| `PUT /account/state` | AccountStateWriteLies | AccountStateWriteLies | AccountStateWriteLies | · | · | · | AccountStateWriteLies |
| `GET /vaults/deleted` | DeletedVaultRestoreLies | DeletedVaultRestoreLies | DeletedVaultRestoreLies | DeletedVaultRestoreLies | DeletedVaultRestoreLies | DeletedVaultRestoreLies | DeletedVaultRestoreLies |
| `POST /items/{id}/restore` | DeletedVaultRestoreLies | · | DeletedVaultRestoreLies | · | · | · | DeletedVaultRestoreLies |
| The event bell (`/events`) | EngineBellLies (core), BellLies | EngineBellLies (core) | EngineBellLies (core) | · | · | BellFrame, BellLies | · |
| `POST /items/{id}/purge` | DeletedVaultRestoreLies | · | DeletedVaultRestoreLies | · | · | · | DeletedVaultRestoreLies |
| `PUT /vaults/{id}/meta` | VaultMetaLies | · | VaultMetaLies | · | · | · | VaultMetaLies |
| `PUT /instance/card` | InstanceCardLies | OtherInstanceLies | InstanceCardLies | · | · | · | InstanceCardLies |
| `POST /account/delete` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `GET /account/totp` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `POST /account/totp/setup` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `PUT /admin/accounts/{id}/quota` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `PUT /admin/policy` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `POST /admin/accounts/{id}/delete` | · | OtherInstanceWritesLies | · | · | · | · | · |
| `POST /signup/verify` | · | `new` OtherInstanceSignupLies | · | · | · | · | · |
| Read by the engine with no scenario yet: `POST /signup/start`, `POST /events/ticket`, `GET /vaults/{id}/members` (not reached, see below), `GET /hibp/range/{prefix}`, `POST /attachments/{id}`, `/downloads/*` (manifest, signature, file) | · | · | · | · | · | · | · |

**Totals.** 67 targets: 58 routes with at least one scenario, the event bell, and 8 routes the engine reads with
none (the last row), across 7 kinds of lie, so 469 cells. The round before covered 203 (197, 192, 186, 179, 144, 128,
112, 86, 72, 56 and 44 before it); this round covers 204. The 1 new: A on sign-up's verify step
(`OtherInstanceSignupLiesTest`), with another public instance's real ticket for its own sign-up: the ticket names
nothing, so it is taken as served (the stated limit), and the registration with it is refused here and makes no
account anywhere. The round before added A on an account's deletion, two-step sign-in's status
and setup, and the operator's quota change, policy change and deletion of an account (`OtherInstanceWritesLiesTest`),
each with another instance's real answer, as its own member or operator got it. `AccountStateCounterLiesTest` (W on
`GET /sync`, a cell already covered) is still switched off and not counted. No new failure. Two-step setup's answer
names an account (its `otpauth` label, `andvari:bob@…`): it is compared with the account it is set up for and refused
(`label_not_this_account`), so no screen is given the other account's secret, and two-step sign-in stays off here. The
other answers name neither the instance nor the account (a time, two flags, four limits, a policy), so each is taken as
served, the stated limit, and decides nothing on this server: a deletion that never reached it leaves the account
standing, a policy that never reached it is unchanged at the next read, a stored quota is the one asked for; and nothing
of this instance's requests reached the other. Earlier: another instance's card answer is a mismatch and moves
no pin; its operator views are shown as served and decide nothing (design §9.2). `POST /auth/end-session` (row 93)
answers nothing the engine reads, so it has no row. The largest gaps, in order of what they could cost the person: the
rest of the last row (sign-up's start, the events ticket, the breach check, a file's upload, the downloads), then T, O and S on
the write routes.

The password rule's list of routes that carry a secret (`World.SECRET_ROUTES`) is held to the server's route table by
`SecretRoutesTest`: setting up two-step sign-in (row 14, a password proof and a code) and the operator's ten † routes
(rows 3, 4, 74 to 76, 78, 79, 81, 85, 86) were missing from it.

## Findings kept as ignored tests

| | One line | Where |
|---|---|---|
| H1 | After a card fork the signed-in account still syncs, pushes items and appends log entries, each with its session token. Item half fixed by the item engine; the log engine and account state remain. | `CardForkTest` |
| H2 | ~~The headless host's sync never fetches or judges the card chain.~~ Fixed by the item engine; passes. | `CardForkTest` |
| H3 | ~~`withheld`, `failed` and "may be incomplete" are never cleared when the server serves the verified head again.~~ Fixed in the engine; passes under the item engine. | `WithholdingTest`, `EquivocationTest` |
| H4 | ~~The headless host never hands an item's `logHead` to the vault-log engine.~~ Fixed by the item engine; passes. | `EquivocationTest` |
| H5 | ~~A vault-record update the ten-minute batching deferred is never written unless a later entry arrives.~~ Fixed in the engine; passes. | `AccountStateTest` |
| H6 | ~~The headless host takes an older `/sync` page as the whole truth.~~ Fixed by the item engine; passes. | `AccountStateTest` |
| H7 | ~~The host's dialer does not send `Host: <origin>`.~~ Declined by the owner on 2026-11-15 (the library that fixed it was taken out): a device that dials another address names that address, so `andvari-cli` refuses `--connect` to any address but the origin's own, and the scenario now states the limit; passes. | `ProxySelfTest` |
| H8 | ~~With an entry unacknowledged, the engine signs a different entry for the same position and forgets the first.~~ Fixed in the engine; passes. | `EquivocationTest` |
| H9 | After a `410 resync_required` the item engine takes an older whole snapshot as the truth: newer items vanish, the sync answers `Synced`, no warning. | `AccountStateTest` |
| H10 | An edit denied while the server took the vault away is dropped as a genuine denial when the vault comes back, never sent again. | `HoldingTest` |
| H11 | ~~The item engine's attachment download calls the uncapped `fetchBytes`, so a body larger than its claim is read whole (64 MiB in the test, then a timeout) before it is refused.~~ Fixed in the vault-content code (`WireAttachments.download` passes the item's claimed size as the cap); passes. | `PinRulesTest` |
| B1 | ~~A bell ring carrying another account's (absurdly high) number becomes `EngineVault.bellRev`; every later honest ring at or below it is ignored until the vault reopens.~~ Fixed in the app interface (`AnsweredRev`: a ring is measured against the rev a pull or push of the opening was answered at, which no ring raises); passes. Fails again if a ring's own number ever becomes the bar. | `EngineBellLiesTest` (core) |
| D1 | ~~The command-line tool's devices reader (`Host.settings`) and the app engine's four `WireAccountSettings` calls pass no `thisDevice`, so another account's whole devices list is shown as the person's devices.~~ Fixed by both hosts (each passes the session's device id); passes. Fails again if `Host.settings` stops passing `thisDevice`, or `DevicePages` stops requiring exactly that device `current`. | `DevicePagesTest` |
| L1 | ~~A create answer's `ttlMs` is taken unbounded (`WireDeviceLinks.create` → `ExistingStep.Shown.ttlMs`, `WireLinkFlows.create` → `CreatedLink.ttlMs`): `-1` shows a live link as run out, `Long.MAX_VALUE` one that never runs out (and `EngineDevices`' `nowMono() + ttlMs` wraps to a deadline in the past).~~ Fixed in the engine: both creates bound it to `[0, the lifetime asked]`; passes. | `CreateAnswerLiesTest` |
| O1 | `WireOperatorRoutes` (what the headless host, and any host, reads the operator's lists through) hands up a self-contradicting list as read: a recovery request twice or with an id outside its grammar, an audit row twice, more than one page of 500, rows outside the filter asked, an account's device marked `current`. The app's `EngineOperator` refuses each whole. Display only (the server speaks about itself), but the hosts disagree, and a request id that is not one is printed as something to type into `recovery-cli assist`. Fix for the owner of `core/client/account/`: move `EngineOperator`'s checks into `WireOperatorRoutes` as `Fetched.Refused(BAD_RESPONSE)`. | `OperatorListLiesTest` |
| S1 | ~~A second device of an account answered "connect first" (password-only) or asked again (linked) for a shared vault the account had accepted on another device: adoption read the answer from this device's own copy of the account state, which no sync read.~~ Fixed in the engine (`StoredVaultLogs` reads the account state once per sync when a vault's latest `add` has no answer held, and re-posts a self-wrap that did not land); passes. | `SecondDeviceTest` (bench and core) |
| H12 | ~~A flood of honest-looking rings is answered with one sync per ring: the app's handler awaited each sync and nothing coalesced.~~ Fixed in the app interface (`EngineVault.startBell` never waits for the sync; rings during a pull cost one more pull); passes with the app's handler. Fails again if `EventBell` waits for a pull before reading the next frame, drops a ring, or drops the socket. | `BellLiesTest` |

## Not reached, and why

- **The baked root in the flows**: the host builds its `CardTrust` with no baked instance, so sign-in and links never
  run under a baked pin. The store-build rules themselves are reached with a trust engine built in the test.
- **A rotation statement signed by a key of the server's own, at a signed-in device's re-seal**: the trust layer's
  builder refuses to sign a rotation whose signer is not the key its `fromFp` names. `RecoveryKeyChangeLiesTest` now
  makes one by hand for the fresh install's open request (a genuine statement re-signed with the new key, from the
  public frame layout `SignedFrame.signedMessage`); the signed-in device's re-seal under a hostile server is not written.
- **Two-step codes**: no scenario enrols two-step sign-in, so no code exists to leak; the routes that would carry one
  are in the recordings the password-rule tests assert on.
- **`bad_claim`, `outer_unopenable`, `bad_outer`, `bad_bundle`, and a bundle that names another origin or instance**: each
  needs a MAC under the link secret or a seal under the account's key, which the server does not hold. They are rows of
  `devicelink.json`. Only the checkpoint case of `pin_mismatch` is reachable from the wire.
- **The served member list** (`GET /vaults/{id}/members`): the engine reads it only through `VaultLogEngine.serverGrants`
  ("no grant, as the server says", which decides nothing; `StoredVaultLogsTest` covers a server that drops a live member),
  and the headless host never calls it; the member list a device shows comes from the verified log.
- **R27's last residual** (a server that fakes the code, the hold and the veto towards an honest operator): there is
  nothing for a client to detect, by design.
- **R24** (web client, extension): not a JVM engine.

## Internal symbols of `:core` reached as a friend module

- `OpenedAccount.signing`: the account's Ed25519 key pair. Used to play T1 as the operator (`Adversary.signCard`), a
  member working with the server (`Adversary.signEntry`), and to sign an account's own genesis for another instance or
  user (`SwappedEnvelopeTest`).
- `OpenedAccount.uvk` (its `copyOut()`): the account key an operator's offline tool would recover from the escrow, to
  build the answer that only the offline recovery key could have made (`RecoveryTest`).

Every statement is built by the public builders of the trust layer (`InstanceCard.sign`, `VaultLog.sign`,
`AccountGenesis.sign`, `RecoveryRotation.sign`, `AssistedRecovery.sign` and `seal`).
