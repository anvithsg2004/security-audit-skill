const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const {
  LIMITS,
  canonicalCoverageId,
  encodeCanonicalRef,
  isSafeAgentId,
  isSafeRelativePath,
  preflightJsonText,
  validateDocument,
} = require("./validate-coverage-ledger.cjs");

const validatorPath = path.join(__dirname, "validate-coverage-ledger.cjs");
const CLI_TIMEOUT_MS = 5000;
const HOSTILE_CLI_TIMEOUT_MS = 15000;
const HAS_SAFE_INPUT_OPEN = Number.isInteger(fs.constants.O_NOFOLLOW) &&
  fs.constants.O_NOFOLLOW !== 0 &&
  Number.isInteger(fs.constants.O_NONBLOCK) &&
  fs.constants.O_NONBLOCK !== 0;

function unit(overrides = {}) {
  const canonicalRefs = overrides.canonical_refs || {
    surface: "src/router.ts#POST /users/:id",
    boundary: "src/authz.ts#requireOwner",
    subsystem: "packages/api",
    attack_class: "ATTACK-CLASSES.md#Access control",
  };
  const value = {
    coverage_id: canonicalCoverageId(canonicalRefs),
    canonical_refs: canonicalRefs,
    surface: "Update-user route",
    boundary: "Object ownership",
    subsystem: "API",
    attack_class: "Access control",
    starting_paths: ["src/router.ts", "src/authz.ts"],
    ordinary_attack_class_block: "ATTACK-CLASSES.md#Access control",
    selected_companion_blocks: [],
    excluded_blocks: [{ block: "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", reason: "The route is not cached." }],
    prior_status: "new",
    attempts: [],
    wave: 1,
    status: "planned",
    agent_id: null,
    reviewed_paths: [],
    local_checks: [],
    result_fingerprints: [],
    unresolved: [],
  };
  return Object.assign(value, overrides, { canonical_refs: canonicalRefs });
}

function errorsFor(value, options) {
  return validateDocument(value, options);
}

function runCli(contents, options = {}) {
  const { nodeArgs = [], timeout = CLI_TIMEOUT_MS, args = [], setup } = options;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-coverage-ledger-"));
  const ledgerPath = path.join(directory, "coverage-ledger.json");
  try {
    fs.writeFileSync(ledgerPath, contents);
    if (typeof setup === "function") setup(directory);
    const cliArgs = args.length > 0 ? args.map((a) => (a === "<ledger>" ? ledgerPath : a)) : [ledgerPath];
    return spawnSync(process.execPath, [...nodeArgs, validatorPath, ...cliArgs], {
      encoding: "utf8",
      timeout,
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function cliOutput(result) {
  return `${result.stdout}${result.stderr}`;
}

const TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e";
const TERMINAL_CONTROL_BYTES = [
  Buffer.from([0x1b]),
  Buffer.from([0x07]),
  Buffer.from("\u0085"),
  Buffer.from("\u202e"),
];

function assertNoInjectedControlBytes(output) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output, "utf8");
  for (const marker of TERMINAL_CONTROL_BYTES) {
    assert.equal(bytes.indexOf(marker), -1, `found raw control bytes ${marker.toString("hex")}`);
  }
}

function sourceCheck(agentId = "hunter-1", overrides = {}) {
  return {
    agent_id: agentId,
    reviewed_paths: ["src/router.ts"],
    invariant: "The route checks object ownership.",
    method: "source",
    result: "The owner check applies before the update.",
    artifact: null,
    ...overrides,
  };
}

function localCheck(agentId = "hunter-1", overrides = {}) {
  return sourceCheck(agentId, {
    method: "local",
    result: "The bounded fixture accepted the other owner's object.",
    artifact: `agents/${agentId}/artifacts/result.txt`,
    ...overrides,
  });
}

function archivedAttempt(overrides = {}) {
  const value = {
    wave: 1,
    status: "blocked",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
    result_fingerprints: [],
    unresolved: ["The deployed policy is unavailable."],
    reassignment_reason: "The critic found an unchecked parallel path.",
  };
  return Object.assign(value, overrides);
}

test("accepts an empty ledger and complete units", () => {
  assert.deepEqual(errorsFor([]), []);
  assert.deepEqual(errorsFor([unit()]), []);

  const missingAttempts = unit();
  delete missingAttempts.attempts;
  assert(errorsFor([missingAttempts]).some((error) => error.includes('missing required field "attempts"')));

  const covered = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
  });
  assert.deepEqual(errorsFor([covered]), []);
});

test("accepts a complete ledger through the CLI", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const result = runCli(JSON.stringify([unit()]));
  assert.equal(result.status, 0, cliOutput(result));
  assert.match(result.stdout, /PASS: 1 coverage units valid/);
});

test("text preflight ignores structural characters and escapes inside strings", () => {
  const value = unit({
    surface: "Route \\ slash [list] {object}, colon: quoted \"value\"",
    excluded_blocks: [{
      block: "COMPANION.md#Literal [brackets] {braces}",
      reason: "The text contains a backslash \\ before an escaped \"quote\".",
    }],
  });
  const contents = JSON.stringify([value]);
  assert.doesNotThrow(() => preflightJsonText(contents));
  assert.deepEqual(JSON.parse(contents), [value]);
  if (HAS_SAFE_INPUT_OPEN) {
    const result = runCli(contents);
    assert.equal(result.status, 0, cliOutput(result));
  }
});

test("text preflight enforces structural cardinality limits", () => {
  const depthLimit = LIMITS.nestingDepth;
  assert.doesNotThrow(() => preflightJsonText(`${"[".repeat(depthLimit)}0${"]".repeat(depthLimit)}`));
  assert.throws(
    () => preflightJsonText(`${"[".repeat(depthLimit + 1)}0${"]".repeat(depthLimit + 1)}`),
    /exceeds nesting depth limit 64/,
  );

  const tooManyUnits = `[${"null,".repeat(LIMITS.units)}null]`;
  assert.throws(() => preflightJsonText(tooManyUnits), /exceeds 10000 top-level unit limit/);

  const tooManyItems = `[[${"null,".repeat(LIMITS.collectionItems)}null]]`;
  assert.throws(() => preflightJsonText(tooManyItems), /exceeds 1000 item array limit/);

  const objectFields = Array.from(
    { length: LIMITS.objectFields + 1 },
    (_, index) => `"field${index}":null`,
  ).join(",");
  assert.throws(() => preflightJsonText(`[{${objectFields}}]`), /exceeds 1000 field object limit/);

  const fullArray = `[${"null,".repeat(LIMITS.collectionItems - 1)}null]`;
  const arraysNeeded = Math.floor(LIMITS.preflightValues / (LIMITS.collectionItems + 1)) + 1;
  const tooManyValues = `[${Array.from({ length: arraysNeeded }, () => fullArray).join(",")}]`;
  assert.throws(() => preflightJsonText(tooManyValues), /exceeds 500000 total value limit/);
});

test("text preflight rejects malformed structural truncation cleanly", () => {
  assert.throws(() => preflightJsonText("["), /truncated JSON structure/);
  assert.throws(() => preflightJsonText("[\"unterminated"), /unterminated JSON string/);
  assert.throws(() => preflightJsonText("[{\"field\":1]"), /mismatched JSON containers/);
});

test("derives collision-free canonical IDs from exact UTF-8 references", () => {
  assert.equal(encodeCanonicalRef("route:POST /users"), "route%3APOST%20%2Fusers");
  assert.notEqual(encodeCanonicalRef("route name"), encodeCanonicalRef("route-name"));
  assert.equal(
    canonicalCoverageId({ surface: "a", boundary: "b", subsystem: "c", attack_class: "d", lifecycle: "retry" }),
    "a::b::c::d::retry",
  );
  assert.throws(() => encodeCanonicalRef("e\u0301"), /invalid canonical reference/);
  assert.throws(() => encodeCanonicalRef("bad\u0000ref"), /invalid canonical reference/);
  assert.throws(() => encodeCanonicalRef("hidden\u200bref"), /invalid canonical reference/);
});

test("rejects noncanonical, duplicate, and colliding IDs", () => {
  const wrong = unit({ coverage_id: "display-label-slug" });
  assert(errorsFor([wrong]).some((error) => error.includes("expected canonical ID")));

  const duplicate = unit();
  assert(errorsFor([duplicate, unit()]).some((error) => error.includes("duplicate coverage ID")));

  const collision = unit();
  const differentMeaning = unit({ surface: "Delete-user route" });
  assert(errorsFor([collision, differentMeaning]).some((error) => error.includes("canonical identity collision")));
});

test("requires canonical references to be own properties", () => {
  const inherited = Object.create(unit().canonical_refs);
  const value = unit();
  value.canonical_refs = inherited;
  assert(errorsFor([value]).some((error) => error.includes("missing required field")));
});

test("rejects aliases for one semantic tuple", () => {
  const first = unit();
  const refs = { ...first.canonical_refs, surface: "src/alias.ts#updateUser" };
  const alias = unit({ canonical_refs: refs });
  const ledger = [first, alias].sort((left, right) => left.coverage_id.localeCompare(right.coverage_id));
  assert(errorsFor(ledger).some((error) => error.includes("semantic tuple already uses coverage ID")));
});

test("requires lexicographic order", () => {
  const secondRefs = {
    surface: "zzz",
    boundary: "src/authz.ts#requireOwner",
    subsystem: "packages/api",
    attack_class: "ATTACK-CLASSES.md#Access control",
  };
  assert(errorsFor([unit({ canonical_refs: secondRefs }), unit()])
    .some((error) => error.includes("sorted lexicographically")));
});

test("validates assignment block maps", () => {
  const overlap = unit({
    selected_companion_blocks: ["AI-AND-LLM.md#Tool calls"],
    excluded_blocks: [{ block: "AI-AND-LLM.md#Tool calls", reason: "Claimed irrelevant." }],
  });
  assert(errorsFor([overlap]).some((error) => error.includes("also selected")));

  const noReason = unit({ excluded_blocks: [{ block: "AI-AND-LLM.md#Tool calls", reason: "" }] });
  assert(errorsFor([noReason]).some((error) => error.includes("reason")));
});

test("requires owned artifacts for local checks and null artifacts for source checks", () => {
  const local = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [localCheck()],
  });
  assert.deepEqual(errorsFor([local]), []);

  const independentlyVerified = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts", "src/authz.ts"],
    local_checks: [sourceCheck(), localCheck("verifier-1", { reviewed_paths: ["src/authz.ts"] })],
  });
  assert.deepEqual(errorsFor([independentlyVerified]), []);

  const unownedPath = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts", "src/authz.ts"],
    local_checks: [sourceCheck()],
  });
  assert(errorsFor([unownedPath]).some((error) => error.includes("has no check owner")));

  for (const [checkAgentId, artifact] of [
    [null, "agents/hunter-1/artifacts/result.txt"],
    ["hunter-1", null],
    ["hunter-1", "result.txt"],
    ["hunter-1", "agents/hunter-2/artifacts/result.txt"],
    ["../hunter", "agents/../hunter/artifacts/result.txt"],
  ]) {
    const value = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck(checkAgentId, { artifact })],
    });
    assert.notEqual(errorsFor([value]).length, 0, `${checkAgentId}: ${artifact}`);
  }

  const unownedSource = unit({
    status: "blocked",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
    unresolved: ["The boundary behavior is not source-visible."],
  });
  assert(errorsFor([unownedSource]).some((error) => error.includes("unit with status \"blocked\" requires a canonical lowercase agent ID")));

  const sourceWithArtifact = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/source.txt" })],
  });
  assert(errorsFor([sourceWithArtifact]).some((error) => error.includes("source-only check must use null")));
});

test("requires canonical lowercase filesystem-safe agent IDs", () => {
  for (const value of ["hunter-1", "verifier_2", "a0"]) assert.equal(isSafeAgentId(value), true, value);
  for (const value of ["Hunter-1", "hunter.1", "hunter-1.", "hunter ", "con", "prn", "aux", "nul", "com1", "lpt9", "../hunter"]) {
    assert.equal(isSafeAgentId(value), false, value);
  }

  const caseAlias = unit({ status: "in_progress", agent_id: "Hunter-1" });
  assert(errorsFor([caseAlias]).some((error) => error.includes("canonical lowercase agent ID")));
});

test("enforces state evidence", () => {
  assert(errorsFor([unit({ status: "in_progress" })]).some((error) => error.includes("unit with status \"in_progress\" requires")));
  assert(errorsFor([unit({ status: "blocked" })]).some((error) => error.includes("unresolved")));
  assert(errorsFor([unit({ status: "candidate" })]).some((error) => error.includes("reviewed_paths")));

  assert.deepEqual(errorsFor([unit({ status: "in_progress", agent_id: "hunter-1" })]), []);
  const inProgressEvidence = unit({
    status: "in_progress",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
  });
  assert(errorsFor([inProgressEvidence]).some((error) => error.includes("must keep this array empty")));

  const assignedPlanned = unit({
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
  });
  assert(errorsFor([assignedPlanned]).some((error) => error.includes("planned unit must be unassigned")));

  const candidate = unit({
    status: "candidate",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck("hunter-1", { invariant: "Ownership is required.", result: "No check exists." })],
    result_fingerprints: ["src-router-missing-owner-check"],
    unresolved: ["validation_budget_exhausted"],
  });
  assert.deepEqual(errorsFor([candidate]), []);

  const blocked = unit({
    status: "blocked",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
    unresolved: ["The deployed policy is unavailable."],
  });
  assert.deepEqual(errorsFor([blocked]), []);
  const blockedFingerprint = { ...blocked, result_fingerprints: ["forbidden-fingerprint"] };
  assert(errorsFor([blockedFingerprint]).some((error) => error.includes("result_fingerprints")));

  for (const status of ["not_applicable", "out_of_scope", "deferred"]) {
    assert.deepEqual(errorsFor([unit({ status, unresolved: ["Reason recorded."] })]), []);
    const invalid = unit({
      status,
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [sourceCheck()],
      result_fingerprints: ["forbidden-fingerprint"],
      unresolved: ["Reason recorded."],
    });
    const errors = errorsFor([invalid]);
    assert(errors.some((error) => error.includes("must be unassigned")), status);
    assert(errors.some((error) => error.includes("reviewed_paths")), status);
    assert(errors.some((error) => error.includes("result_fingerprints")), status);
  }

  const coveredFingerprint = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
    result_fingerprints: ["forbidden-fingerprint"],
  });
  assert(errorsFor([coveredFingerprint]).some((error) => error.includes("result_fingerprints")));

  const coveredUnresolved = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck()],
    unresolved: ["Unexpected unresolved claim."],
  });
  assert(errorsFor([coveredUnresolved]).some((error) => error.includes("unresolved")));
});

test("archives prior evidence when a critic assigns a fresh owner", () => {
  const reassigned = unit({
    attempts: [archivedAttempt()],
    wave: 2,
    status: "in_progress",
    agent_id: "hunter-2",
  });
  assert.deepEqual(errorsFor([reassigned]), []);

  const finalClosure = unit({
    attempts: [archivedAttempt()],
    wave: 2,
    status: "covered",
    agent_id: "hunter-2",
    reviewed_paths: ["src/authz.ts"],
    local_checks: [sourceCheck("hunter-2", { reviewed_paths: ["src/authz.ts"] })],
  });
  assert.deepEqual(errorsFor([finalClosure]), []);
});

test("preserves candidate provenance when reassignment must be deferred", () => {
  const candidateAttempt = archivedAttempt({
    status: "candidate",
    result_fingerprints: ["src-router-missing-owner-check"],
    unresolved: ["validation_budget_exhausted"],
  });
  const deferred = unit({
    attempts: [candidateAttempt],
    wave: 2,
    status: "deferred",
    unresolved: ["quick_profile_final_critic"],
  });
  assert.deepEqual(errorsFor([deferred]), []);
});

test("rejects reassignment owner reuse and evidence mixing", () => {
  const reusedOwner = unit({
    attempts: [archivedAttempt()],
    wave: 2,
    status: "in_progress",
    agent_id: "hunter-1",
  });
  assert(errorsFor([reusedOwner]).some((error) => error.includes("current assignment owner must be fresh")));

  const mixedEvidence = unit({
    attempts: [archivedAttempt({ local_checks: [localCheck()] })],
    wave: 2,
    status: "covered",
    agent_id: "hunter-2",
    reviewed_paths: ["src/router.ts"],
    local_checks: [localCheck()],
  });
  const errors = errorsFor([mixedEvidence]);
  assert(errors.some((error) => error.includes("prior assignment owner evidence must remain")));
  assert(errors.some((error) => error.includes("artifact from an archived attempt cannot be reused")));

  const mixedHistory = unit({
    attempts: [
      archivedAttempt({ local_checks: [localCheck()] }),
      archivedAttempt({
        wave: 2,
        agent_id: "hunter-2",
        local_checks: [localCheck()],
      }),
    ],
    wave: 3,
    status: "in_progress",
    agent_id: "hunter-3",
  });
  const historyErrors = errorsFor([mixedHistory]);
  assert(historyErrors.some((error) => error.includes("prior assignment owner evidence must remain in its earlier attempt")));
  assert(historyErrors.some((error) => error.includes("artifact from an earlier attempt cannot be reused")));

  const unordered = unit({
    attempts: [archivedAttempt(), archivedAttempt({
      wave: 1,
      agent_id: "hunter-2",
      local_checks: [sourceCheck("hunter-2")],
    })],
    wave: 3,
    status: "in_progress",
    agent_id: "hunter-3",
  });
  assert(errorsFor([unordered]).some((error) => error.includes("strictly increasing")));
});

test("rejects unsafe paths and malformed fingerprints", () => {
  for (const value of [
    "/etc/passwd",
    "../src/file.js",
    "src/../file.js",
    "src/con.txt",
    "src/PRN",
    "src/AUX.c",
    "src/NUL",
    "src/CLOCK$.txt",
    "src/conin$.txt",
    "src/conout$",
    "src/COM1.log",
    "src/lpt9",
    "src/COM\u00b9.log",
    "src/COM\u00b2.log",
    "src/COM\u00b3.log",
    "src/lpt\u00b9",
    "src/lpt\u00b2",
    "src/lpt\u00b3",
    "src/file.js.",
    "C:/src/file.js",
    "src/file\n.js",
    "src/file\u0085.js",
    "src/file\u2028.js",
    "src/file\u200b.js",
    "src/file\u034f.js",
    "src/file\ufe0f.js",
  ]) {
    assert.equal(isSafeRelativePath(value), false, value);
  }
  assert.equal(isSafeRelativePath("src/handler.js"), true);
  assert.equal(isSafeRelativePath("src/caf\u00e9/handler.js"), true);
  assert(errorsFor([unit({ starting_paths: ["../src/router.ts"] })]).some((error) => error.includes("repository-relative path")));
  assert(errorsFor([unit({
    status: "candidate",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [sourceCheck("hunter-1", { invariant: "Ownership is required.", result: "No check exists." })],
    result_fingerprints: ["not stable"],
  })]).some((error) => error.includes("invalid fingerprint")));
});

test("rejects format, default-ignorable, and invalid-scalar prose", () => {
  for (const invisible of ["\u200b", "\u034f", "\ufe0f", "\ud800"]) {
    assert(errorsFor([unit({ surface: invisible })]).some((error) => error.includes("surface")), JSON.stringify(invisible));
    assert(errorsFor([unit({
      excluded_blocks: [{ block: "ATTACK-CLASSES.md#Access control", reason: invisible }],
    })]).some((error) => error.includes("reason")), JSON.stringify(invisible));
  }
});

test("quotes input-derived controls in direct validation errors", () => {
  const invalidStatus = `invalid-${TERMINAL_CONTROL_PAYLOAD}`;
  const invalidPath = `src/${TERMINAL_CONTROL_PAYLOAD}.js`;
  const value = unit({
    status: invalidStatus,
    agent_id: "hunter-1",
    reviewed_paths: [invalidPath],
    local_checks: [sourceCheck()],
    result_fingerprints: ["force-state-error"],
  });
  const output = errorsFor([value]).join("\n");

  assert.match(output, /\$\[0\]\.status/);
  assert.match(output, /\$\[0\]\.reviewed_paths/);
  assert.match(output, /\\u001b/);
  assert.match(output, /\\u0007/);
  assert.match(output, /\\u0085/);
  assert.match(output, /\\u202e/);
  assertNoInjectedControlBytes(output);
});

test("quotes input-derived controls in CLI validation errors", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const value = unit({
    status: `invalid-${TERMINAL_CONTROL_PAYLOAD}`,
    result_fingerprints: ["force-state-error"],
  });
  const result = runCli(JSON.stringify([value]));

  assert.equal(result.status, 1, cliOutput(result));
  assert.match(result.stderr, /\$\[0\]\.status/);
  assert.match(result.stderr, /\\u001b/);
  assertNoInjectedControlBytes(result.stderr);
});

test("returns a generic syntax error without parser-supplied controls", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const malformed = Buffer.concat([
    Buffer.from("["),
    Buffer.from(TERMINAL_CONTROL_PAYLOAD),
    Buffer.from("]"),
  ]);
  const result = runCli(malformed);

  assert.equal(result.status, 1, cliOutput(result));
  assert.equal(result.stderr, "Failed to parse coverage ledger: invalid JSON syntax\n");
  assertNoInjectedControlBytes(result.stderr);
});

test("does not reflect controls from a failed CLI input path", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-coverage-ledger-path-"));
  const missingPath = path.join(directory, `missing-${TERMINAL_CONTROL_PAYLOAD}.json`);
  try {
    const result = spawnSync(process.execPath, [validatorPath, missingPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    assert.equal(result.status, 1, cliOutput(result));
    assert.match(result.stderr, /Failed to read coverage ledger:/);
    assertNoInjectedControlBytes(result.stderr);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects invalid UTF-8 through the CLI", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const encoded = Buffer.from(JSON.stringify([unit()]));
  const marker = Buffer.from("Update-user route");
  const markerOffset = encoded.indexOf(marker);
  assert.notEqual(markerOffset, -1);
  const malformed = Buffer.concat([
    encoded.subarray(0, markerOffset),
    Buffer.from([0x80]),
    encoded.subarray(markerOffset + marker.length),
  ]);

  const result = runCli(malformed);
  const output = cliOutput(result);
  assert.equal(result.status, 1, output);
  assert.match(output, /input is not valid UTF-8/);
  assert.doesNotMatch(output, /TypeError|stack|at validate-coverage-ledger/i);
});

test("rejects a FIFO through the CLI without blocking", { skip: process.platform === "win32" || !HAS_SAFE_INPUT_OPEN }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-coverage-ledger-fifo-"));
  const fifoPath = path.join(directory, "coverage-ledger.json");
  try {
    const created = spawnSync("mkfifo", [fifoPath], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
    assert.equal(created.status, 0, cliOutput(created));

    const result = spawnSync(process.execPath, [validatorPath, fifoPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 1, output);
    assert.match(output, /input must be a regular file/);
    assert.doesNotMatch(output, /stack|at validate-coverage-ledger/i);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a symlink through the CLI", { skip: process.platform === "win32" || !HAS_SAFE_INPUT_OPEN }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-coverage-ledger-symlink-"));
  const targetPath = path.join(directory, "target.json");
  const symlinkPath = path.join(directory, "coverage-ledger.json");
  try {
    fs.writeFileSync(targetPath, JSON.stringify([unit()]));
    fs.symlinkSync(targetPath, symlinkPath);
    const result = spawnSync(process.execPath, [validatorPath, symlinkPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 1, output);
    assert.match(output, /input must not be a symlink/);
    assert.doesNotMatch(output, /stack|at validate-coverage-ledger/i);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects deeply nested input without recursion failure", () => {
  let nested = 0;
  for (let depth = 0; depth < 20000; depth++) nested = [nested];
  assert(errorsFor(nested).some((error) => error.includes("exceeds nesting depth limit 64")));
  if (!HAS_SAFE_INPUT_OPEN) return;

  const result = runCli(`${"[".repeat(20000)}0${"]".repeat(20000)}`);
  const output = cliOutput(result);
  assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
  assert.equal(result.status, 1, output);
  assert.match(output, /exceeds nesting depth limit 64/);
  assert.doesNotMatch(output, /RangeError|Maximum call stack|stack|at validate-coverage-ledger/i);
});

test("rejects multi-megabyte nesting under a constrained Node heap", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const openContainers = "[".repeat(2000000);
  const cases = [
    openContainers,
    `${openContainers}0${"]".repeat(2000000)}`,
  ];
  for (const contents of cases) {
    const result = runCli(contents, {
      nodeArgs: ["--max-old-space-size=64"],
      timeout: HOSTILE_CLI_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 1, output);
    assert.match(output, /exceeds nesting depth limit 64/);
    assert.doesNotMatch(output, /heap out of memory|allocation failed|RangeError|Maximum call stack|stack|at validate-coverage-ledger/i);
  }
});

test("caps malformed 10000-unit validation output", () => {
  assert.equal(errorsFor(Array.from({ length: LIMITS.units }, () => null)).length, LIMITS.validationErrors);
  if (!HAS_SAFE_INPUT_OPEN) return;

  const result = runCli(JSON.stringify(Array.from({ length: LIMITS.units }, () => null)));
  const output = cliOutput(result);
  assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
  assert.equal(result.status, 1, output);
  assert.match(output, /output capped at 100/);
  assert(output.length < 20000, `unexpected output length ${output.length}`);
  assert.doesNotMatch(output, /RangeError|Maximum call stack|stack|at validate-coverage-ledger/i);
});

test("rejects malformed top-level data and excessive unit counts", () => {
  assert.deepEqual(errorsFor({ units: [] }), ["$: expected a top-level array"]);
  const tooMany = Array.from({ length: 10001 }, () => null);
  const errors = errorsFor(tooMany);
  assert.deepEqual(errors, ["$: exceeds 10000 coverage units"]);

  const oversizedCollection = unit({ extra: Array.from({ length: LIMITS.collectionItems + 1 }, () => null) });
  assert(errorsFor([oversizedCollection]).some((error) => error.includes("exceeds 1000 entries")));
});

test("accepts a canonical ID derived from near-maximum multibyte references", () => {
  const canonicalRefs = {
    surface: "\u6f22".repeat(1024),
    boundary: "\u00e9".repeat(1024),
    subsystem: "packages/api",
    attack_class: "\u6f22".repeat(1023) + "\u00e9",
  };
  const value = unit({ canonical_refs: canonicalRefs });
  assert(value.coverage_id.length > 16384, `coverage_id length ${value.coverage_id.length}`);
  assert(value.coverage_id.length <= 65536, `coverage_id length ${value.coverage_id.length}`);
  assert.deepEqual(errorsFor([value]), []);

  if (HAS_SAFE_INPUT_OPEN) {
    const result = runCli(JSON.stringify([value]));
    assert.equal(result.status, 0, cliOutput(result));
  }
});

test("validates local check artifact existence and properties on disk", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "artifact-test-"));
  try {
    const hunterArtifacts = path.join(directory, "agents", "hunter-1", "artifacts");
    fs.mkdirSync(hunterArtifacts, { recursive: true });

    // 1. Nonexistent artifact
    const missing = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing.txt" })],
    });
    const missingErrors = errorsFor([missing], { baseDir: directory });
    assert(missingErrors.some((e) => e.includes("$[0].local_checks[0].artifact: local check artifact does not exist")));

    // 2. Valid regular file
    const validFile = path.join(hunterArtifacts, "result.txt");
    fs.writeFileSync(validFile, "local test output");
    const valid = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/result.txt" })],
    });
    assert.deepEqual(errorsFor([valid], { baseDir: directory }), []);

    // 3. Directory artifact
    const subDir = path.join(hunterArtifacts, "sub-dir");
    fs.mkdirSync(subDir, { recursive: true });
    const dirUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/sub-dir" })],
    });
    const dirErrors = errorsFor([dirUnit], { baseDir: directory });
    assert(dirErrors.some((e) => e.includes("$[0].local_checks[0].artifact: local check artifact must be a regular file")));

    // 4. Symlink artifact (if supported on host)
    let canSymlink = false;
    const symlinkPath = path.join(hunterArtifacts, "symlink.txt");
    try {
      fs.symlinkSync(validFile, symlinkPath);
      canSymlink = true;
    } catch {
      // Symlinks may require elevated privileges on Windows
    }
    if (canSymlink) {
      const symlinkUnit = unit({
        status: "covered",
        agent_id: "hunter-1",
        reviewed_paths: ["src/router.ts"],
        local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/symlink.txt" })],
      });
      const symErrors = errorsFor([symlinkUnit], { baseDir: directory });
      assert(symErrors.some((e) => e.includes("$[0].local_checks[0].artifact: local check artifact must not be a symlink")));
      fs.unlinkSync(symlinkPath);
    }

    // 5. Escaping agent artifacts directory via directory symlink
    if (canSymlink) {
      const outsideDir = path.join(directory, "outside");
      fs.mkdirSync(outsideDir, { recursive: true });
      fs.writeFileSync(path.join(outsideDir, "outside.txt"), "outside content");
      const symDir = path.join(hunterArtifacts, "escaped");
      try {
        fs.symlinkSync(outsideDir, symDir, "dir");
        const escapeUnit = unit({
          status: "covered",
          agent_id: "hunter-1",
          reviewed_paths: ["src/router.ts"],
          local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/escaped/outside.txt" })],
        });
        const escapeErrors = errorsFor([escapeUnit], { baseDir: directory });
        assert(escapeErrors.some((e) => e.includes("$[0].local_checks[0].artifact: local check artifact must reside inside agent artifacts directory")));
      } finally {
        try { fs.unlinkSync(symDir); } catch {}
      }
    }

    // 6. Attempts history also validates artifacts on disk
    const attemptWithMissing = unit({
      attempts: [archivedAttempt({
        local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing-attempt.txt" })],
      })],
      wave: 2,
      status: "covered",
      agent_id: "hunter-2",
      reviewed_paths: ["src/router.ts"],
      local_checks: [sourceCheck("hunter-2")],
    });
    const attemptErrors = errorsFor([attemptWithMissing], { baseDir: directory });
    assert(attemptErrors.some((e) => e.includes("$[0].attempts[0].local_checks[0].artifact: local check artifact does not exist")));

    const attemptValidFile = path.join(hunterArtifacts, "attempt-result.txt");
    fs.writeFileSync(attemptValidFile, "attempt evidence");
    const attemptWithValid = unit({
      attempts: [archivedAttempt({
        local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/attempt-result.txt" })],
      })],
      wave: 2,
      status: "covered",
      agent_id: "hunter-2",
      reviewed_paths: ["src/router.ts"],
      local_checks: [sourceCheck("hunter-2")],
    });
    assert.deepEqual(errorsFor([attemptWithValid], { baseDir: directory }), []);

    // 7. Schema-only validation ignores disk checks when baseDir is omitted
    assert.deepEqual(errorsFor([missing]), []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("validates local check artifacts through the CLI", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  // 1. Missing artifact causes CLI to fail
  const missingUnit = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing.txt" })],
  });
  const failResult = runCli(JSON.stringify([missingUnit]));
  const failOutput = cliOutput(failResult);
  assert.equal(failResult.status, 1, failOutput);
  assert.match(failOutput, /\$\[0\]\.local_checks\[0\]\.artifact: local check artifact does not exist/);

  // 2. Present artifact causes CLI to succeed
  const presentUnit = unit({
    status: "covered",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/result.txt" })],
  });
  const passResult = runCli(JSON.stringify([presentUnit]), {
    setup(dir) {
      const artDir = path.join(dir, "agents", "hunter-1", "artifacts");
      fs.mkdirSync(artDir, { recursive: true });
      fs.writeFileSync(path.join(artDir, "result.txt"), "retained artifact content");
    },
  });
  const passOutput = cliOutput(passResult);
  assert.equal(passResult.status, 0, passOutput);
  assert.match(passOutput, /PASS: 1 coverage units valid/);

  // 3. CLI --output-dir specifies custom base directory
  const customDir = fs.mkdtempSync(path.join(os.tmpdir(), "custom-out-"));
  try {
    const customArtDir = path.join(customDir, "agents", "hunter-1", "artifacts");
    fs.mkdirSync(customArtDir, { recursive: true });
    fs.writeFileSync(path.join(customArtDir, "result.txt"), "custom dir artifact");

    const customPassResult = runCli(JSON.stringify([presentUnit]), {
      args: ["<ledger>", "--output-dir", customDir],
    });
    const customPassOutput = cliOutput(customPassResult);
    assert.equal(customPassResult.status, 0, customPassOutput);
    assert.match(customPassOutput, /PASS: 1 coverage units valid/);
  } finally {
    fs.rmSync(customDir, { recursive: true, force: true });
  }

  // 4. CLI --schema-only flag bypasses artifact check
  const schemaOnlyResult = runCli(JSON.stringify([missingUnit]), {
    args: ["<ledger>", "--schema-only"],
  });
  const schemaOnlyOutput = cliOutput(schemaOnlyResult);
  assert.equal(schemaOnlyResult.status, 0, schemaOnlyOutput);
  assert.match(schemaOnlyOutput, /PASS: 1 coverage units valid/);
});

test("validates local check artifact edge cases", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "artifact-edge-cases-"));
  try {
    const hunterArtifacts = path.join(directory, "agents", "hunter-1", "artifacts");
    fs.mkdirSync(hunterArtifacts, { recursive: true });

    // 1. 0-byte empty regular file is valid
    const emptyFile = path.join(hunterArtifacts, "empty.txt");
    fs.writeFileSync(emptyFile, "");
    const emptyUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/empty.txt" })],
    });
    assert.deepEqual(errorsFor([emptyUnit], { baseDir: directory }), []);

    // 2. Deeply nested file inside artifacts directory is valid
    const deepDir = path.join(hunterArtifacts, "level1", "level2", "level3");
    fs.mkdirSync(deepDir, { recursive: true });
    const deepFile = path.join(deepDir, "deep.log");
    fs.writeFileSync(deepFile, "deep log content");
    const deepUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/level1/level2/level3/deep.log" })],
    });
    assert.deepEqual(errorsFor([deepUnit], { baseDir: directory }), []);

    // 3. Valid Unicode (NFC normalized) artifact filename
    const unicodeFile = path.join(hunterArtifacts, "caf\u00e9.txt");
    fs.writeFileSync(unicodeFile, "caf\u00e9 report");
    const unicodeUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/caf\u00e9.txt" })],
    });
    assert.deepEqual(errorsFor([unicodeUnit], { baseDir: directory }), []);

    // 4. Multiple checks in one unit: check 0 source, check 1 valid local, check 2 missing local
    const presentFile = path.join(hunterArtifacts, "present.txt");
    fs.writeFileSync(presentFile, "evidence");
    const mixedChecksUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts", "src/authz.ts", "src/user.ts"],
      local_checks: [
        sourceCheck("hunter-1", { reviewed_paths: ["src/router.ts"] }),
        localCheck("hunter-1", { reviewed_paths: ["src/authz.ts"], artifact: "agents/hunter-1/artifacts/present.txt" }),
        localCheck("hunter-1", { reviewed_paths: ["src/user.ts"], artifact: "agents/hunter-1/artifacts/missing-third.txt" }),
      ],
    });
    const mixedErrors = errorsFor([mixedChecksUnit], { baseDir: directory });
    assert.equal(mixedErrors.length, 1);
    assert.equal(mixedErrors[0], "$[0].local_checks[2].artifact: local check artifact does not exist");

    // 5. Blocked and candidate units also validate artifact on disk
    const blockedUnit = unit({
      status: "blocked",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing-blocked.txt" })],
      unresolved: ["Deployment configuration is unavailable."],
    });
    const blockedErrors = errorsFor([blockedUnit], { baseDir: directory });
    assert(blockedErrors.some((e) => e === "$[0].local_checks[0].artifact: local check artifact does not exist"));

    const candidateUnit = unit({
      status: "candidate",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing-candidate.txt" })],
      result_fingerprints: ["router-authz-bypass"],
      unresolved: ["validation_budget_exhausted"],
    });
    const candidateErrors = errorsFor([candidateUnit], { baseDir: directory });
    assert(candidateErrors.some((e) => e === "$[0].local_checks[0].artifact: local check artifact does not exist"));

    // 6. Multiple units in one ledger: error points at specific unit index
    const unit0 = unit({
      coverage_id: canonicalCoverageId({
        surface: "src/router.ts#GET /users",
        boundary: "src/authz.ts#requireViewer",
        subsystem: "packages/api",
        attack_class: "ATTACK-CLASSES.md#Access control",
      }),
      canonical_refs: {
        surface: "src/router.ts#GET /users",
        boundary: "src/authz.ts#requireViewer",
        subsystem: "packages/api",
        attack_class: "ATTACK-CLASSES.md#Access control",
      },
      surface: "List-users route",
      boundary: "Viewer permission",
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/present.txt" })],
    });
    const unit1 = unit({
      coverage_id: canonicalCoverageId({
        surface: "src/router.ts#POST /users",
        boundary: "src/authz.ts#requireAdmin",
        subsystem: "packages/api",
        attack_class: "ATTACK-CLASSES.md#Access control",
      }),
      canonical_refs: {
        surface: "src/router.ts#POST /users",
        boundary: "src/authz.ts#requireAdmin",
        subsystem: "packages/api",
        attack_class: "ATTACK-CLASSES.md#Access control",
      },
      surface: "Create-user route",
      boundary: "Admin permission",
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/missing-in-unit1.txt" })],
    });
    const sortedLedger = [unit0, unit1].sort((a, b) => a.coverage_id.localeCompare(b.coverage_id));
    const badIndex = sortedLedger.indexOf(unit1);
    const multiErrors = errorsFor(sortedLedger, { baseDir: directory });
    assert.equal(multiErrors.length, 1);
    assert.equal(multiErrors[0], `$[${badIndex}].local_checks[0].artifact: local check artifact does not exist`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI accepts --base-dir and --output-dir with equals syntax", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const customDir = fs.mkdtempSync(path.join(os.tmpdir(), "custom-cli-flags-"));
  try {
    const artDir = path.join(customDir, "agents", "hunter-1", "artifacts");
    fs.mkdirSync(artDir, { recursive: true });
    fs.writeFileSync(path.join(artDir, "result.txt"), "valid content");

    const validUnit = unit({
      status: "covered",
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      local_checks: [localCheck("hunter-1", { artifact: "agents/hunter-1/artifacts/result.txt" })],
    });

    // 1. --base-dir <dir>
    const baseDirRes = runCli(JSON.stringify([validUnit]), {
      args: ["<ledger>", "--base-dir", customDir],
    });
    assert.equal(baseDirRes.status, 0, cliOutput(baseDirRes));

    // 2. --output-dir=<dir>
    const outputDirEqRes = runCli(JSON.stringify([validUnit]), {
      args: ["<ledger>", `--output-dir=${customDir}`],
    });
    assert.equal(outputDirEqRes.status, 0, cliOutput(outputDirEqRes));

    // 3. --base-dir=<dir>
    const baseDirEqRes = runCli(JSON.stringify([validUnit]), {
      args: ["<ledger>", `--base-dir=${customDir}`],
    });
    assert.equal(baseDirEqRes.status, 0, cliOutput(baseDirEqRes));
  } finally {
    fs.rmSync(customDir, { recursive: true, force: true });
  }
});


