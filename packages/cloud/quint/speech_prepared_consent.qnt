// One server-generated consent and its prepared speech object.
// Legacy random recovery IDs retain the existing Redis path.
module speech_prepared_consent {
  var phase: str
  var live: bool
  var admissions: int
  var armed: bool
  var credential: str
  action init = all { phase' = "absent", live' = true, admissions' = 0, armed'=false, credential' = "checking" }
  action check(result: str): bool = all {
    Set("checking", "retrying").contains(credential),
    credential' = if (result == "allowed") "allowed"
      else if (result == "timeout" and credential == "checking") "retrying"
      else "refused",
    phase' = phase, live' = live, admissions' = admissions, armed' = armed
  }
  action authorize = check("allowed")
  action prepare = all { phase == "absent", live, credential == "allowed",
    phase' = "prepared", live' = live, admissions' = admissions, armed'=true, credential' = credential }
  action expire = all { live, live' = false, phase' = phase, admissions' = admissions, armed'=false, credential' = credential }
  action retire = all { phase != "retired", phase' = "retired", live' = live, admissions' = admissions, armed'=false, credential' = credential }
  action mint(ownerMatches: bool, nonceMatches: bool): bool = {
    val accepted = phase == "prepared" and live and ownerMatches and nonceMatches
    all { phase' = if (accepted) "minted" else phase,
      admissions' = if (accepted) admissions + 1 else admissions,
      live' = live, armed'=armed, credential' = credential }
  }
  // New prepared nonces have no Redis entry, so the legacy route cannot mint them.
  action legacyAttempt = all { admissions' = admissions, phase' = phase, live' = live, armed'=armed, credential' = credential }
  action restart = all { phase' = phase, live' = live, admissions' = admissions, armed'=armed, credential' = credential }
  action failedPrepare = all {phase=="absent",phase'=phase,live'=live,admissions'=admissions,armed'=armed, credential' = credential}
  action step = any { prepare, failedPrepare, expire, retire, legacyAttempt, restart,
    { nondet result = Set("allowed", "denied", "timeout", "canceled").oneOf(); check(result) },
    { nondet ownerMatches = Bool.oneOf(); nondet nonceMatches = Bool.oneOf(); mint(ownerMatches, nonceMatches) } }
  val SingleUse = admissions <= 1
  val ValidPhase = Set("absent", "prepared", "minted", "retired").contains(phase)
  val NoAdmissionWithoutPrepare = phase != "absent" or admissions == 0
  val ArmedBeforeMint = phase == "prepared" and live implies armed
  val NoPrepareWithoutAuthorization = Set("prepared", "minted").contains(phase) implies credential == "allowed"
  val safety = SingleUse and ValidPhase and NoAdmissionWithoutPrepare and ArmedBeforeMint and NoPrepareWithoutAuthorization
  run coldCredentialRechecked = init.then(check("timeout")).then(authorize).then(prepare).expect(phase == "prepared" and safety)
  run deniedAfterTimeout = init.then(check("timeout")).then(check("denied")).expect(credential == "refused" and phase == "absent" and safety)
  run repeatedTimeoutFailsClosed = init.then(check("timeout")).then(check("timeout")).expect(credential == "refused" and phase == "absent" and safety)
  run stopAfterTimeout = init.then(check("timeout")).then(check("canceled")).expect(credential == "refused" and phase == "absent" and safety)
  run failedPreparationLeavesNothing = init.then(failedPrepare).expect(phase=="absent" and not(armed) and safety)
  run replayAfterRestart = init.then(authorize).then(prepare).then(mint(true, true)).then(restart).then(mint(true, true)).expect(admissions == 1 and safety)
  run wrongOwner = init.then(authorize).then(prepare).then(mint(false, true)).expect(admissions == 0 and safety)
  run wrongNonce = init.then(authorize).then(prepare).then(mint(true, false)).expect(admissions == 0 and safety)
  run expiredConsent = init.then(authorize).then(prepare).then(expire).then(mint(true, true)).expect(admissions == 0 and safety)
  run retiredConsent = init.then(authorize).then(prepare).then(retire).then(mint(true, true)).expect(admissions == 0 and safety)
  run missingPreparation = init.then(mint(true, true)).expect(admissions == 0 and safety)
  run crossRouteReplay = init.then(authorize).then(prepare).then(mint(true, true)).then(legacyAttempt).expect(admissions == 1 and safety)
}
