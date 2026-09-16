#!/usr/bin/env python3
"""repo-guard.py -- the portable guard engine every repo runs in CI.

    python .github/guards/repo-guard.py <check> [--root DIR]
    python .github/guards/repo-guard.py --selftest

    checks:  capabilities | tier0 | lint | security | graphify | automerge

EXIT CODES -- the split S5 introduced (finding A-24) and this file inherits deliberately:

    0  PASS
    1  a real finding. Fail the job.
    2  ENVIRONMENT ERROR -- could not run. NEVER use 2 for "I looked and found nothing wrong";
       that is 0. Note the asymmetry, because the first draft of this docstring overstated it:
       dev-main's OWN gates.yml folds a 2 to a skip, but repo-guards.yml -- the workflow this file
       actually ships inside, in all 12 repos -- does not, so a 2 fails the job there like any
       other non-zero. That is the safer direction and is left as is; the docstring was what was
       wrong. (s35 reviewer.)
    3  SELFTEST FAILURE. Outside the folded range on purpose, so a guard whose own controls are
       broken cannot be reported green by CI. Before S5, exit 2 meant both "skip me" and "I am
       broken", and CI folded both to success.

WHY A SCRIPT AND NOT YAML. Guard logic buried in a run: block can only be exercised by pushing to
CI, which makes its must-fire control a thing you assert rather than run. CLAUDE.md section 11
requires every gate to ship a two-sided control, and section 9 refuse-pattern 7 makes shipping a
gate proven only on the passing case a refusal. --selftest below runs BOTH directions of every
check against synthetic trees, locally, in about a second. The YAML is a thin wrapper.

THE CONTRACT WITH .github/repo-capabilities.yml. Each check asserts the declaration against the
tree in both directions -- see that file's header for the truth table. The short version: a false
flag is a CLAIM, not an off-switch, and an undeclared surface that exists is a FAILURE.
"""
import argparse
import json
import os
import re
import subprocess
import shutil
import sys
import tempfile

CAPS_REL = os.path.join(".github", "repo-capabilities.yml")
SURFACES = ("tier0", "edge_functions", "graphify", "node", "python")

# Actions published by GitHub itself. Everything else must be sha-pinned. These are still worth
# pinning and are allowed unpinned only because requiring it of actions/* in one change would turn
# every existing repo red on day one for a lower-severity issue than a third party can cause.
FIRST_PARTY = ("actions/", "github/")


def out(msg):
    sys.stdout.write(msg + "\n")


def fail(title, msg):
    out("::error title=%s::%s" % (title, msg))
    return 1


# -------------------------------------------------------------------------------------------------
# capability manifest
# -------------------------------------------------------------------------------------------------
_GITDIR_CACHE = {}


def _is_real_checkout(path):
    """Is `path` genuinely a nested repo or worktree? ASK GIT, do not re-implement it.

    THIS TEST LOST SIX CONSECUTIVE REVIEW ROUNDS before it converged:

        round 2   os.path.exists('.git')          an empty FILE named .git passed
        round 3   .git/HEAD must exist            an empty .git/HEAD passed
        round 4   HEAD must look like a ref       `gitdir: nope` passed
        round 5   the target must exist           `gitdir: .` passed; an empty config passed
        round 6   ask git (rev-parse)             git's discovery walks UP -- a `.git` dir with one
                                                  file made git answer about the ANCESTOR, rc=0
        round 6b  require containment             REJECTED EVERY REAL LINKED WORKTREE, whose git-dir
                                                  lives under the MAIN repo, not the worktree
        round 7   different from the parent       a `.git` FILE may point at a FOREIGN real repo;
                                                  git accepts it, so "different" was true

    Each round closed exactly the forgery it had been shown. That is not four mistakes, it is one:
    hand-rolling a heuristic for "is this a git repository" against an adversary who can write any
    file, when git itself answers the question definitively and is already a hard dependency of
    every job that calls this. The s42 future-proofing-auditor named it in round 5 -- an arms race
    with no end -- and named the exit.

    So: `git rev-parse --git-dir` from inside the directory. Git resolves worktree pointers, nested
    clones and submodules correctly by construction, and rejects a fabricated `.git` because it
    actually tries to USE it. A forgery now has to satisfy git, not a regex.

    The fallback is deliberate and narrow. If git is absent or errors, fall back to requiring a
    `.git` that at least resolves -- weaker, but it FAILS CLOSED toward scanning: an unrecognised
    directory is WALKED (linted, scanned for secrets) rather than skipped. For a guard, walking
    something you should have skipped costs a false positive; skipping something you should have
    walked is how a credential hides.
    """
    marker = os.path.join(path, ".git")
    if not os.path.exists(marker):
        return False
    try:
        # ASK GIT, THEN ASK ITS PARENT, AND COMPARE. Asking git is only half of it: git's discovery
        # walks UP, so inside any real repo a forged `.git` that fails local validation does not make
        # git error -- it makes git answer about the ANCESTOR. `.git/config` alone was enough: rc=0,
        # git-dir = the parent repo's, and a naive exit-code check pruned the subtree, hiding what
        # was in it from the lint AND the secret scan.
        #
        # THE OBVIOUS FIX -- require the git-dir to live UNDER this directory -- IS WRONG, and shipped
        # broken for one commit. A linked worktree's git-dir is at <main>/.git/worktrees/<name>, which
        # is NEVER under the worktree. Containment therefore REJECTED every real worktree, and this
        # repo has two: the walk re-entered exactly the directories the rule exists to exclude.
        #
        # The correct question is not "where is the git-dir" but "IS THIS A DIFFERENT CHECKOUT FROM
        # ITS PARENT". A separate checkout -- nested clone, submodule or linked worktree -- resolves
        # to a git-dir the parent does NOT resolve to. A forgery, and an ordinary subdirectory,
        # resolve to the same one the parent does. That holds for all four shapes without knowing
        # anything about git's layout. (s42 defect-hunter r6 found the evasion; future-proofing r6
        # found this regression in the fix for it.)
        def _gitdir(d):
            # CACHED. `theirs` is the same answer for every sibling in a directory, and _prune()
            # asks once per child -- N redundant subprocess spawns for one fact.
            # (s42 defect-hunter, round 7.)
            key = os.path.normcase(os.path.realpath(d))
            if key in _GITDIR_CACHE:
                return _GITDIR_CACHE[key]
            rr = subprocess.run(["git", "-C", d, "rev-parse", "--absolute-git-dir"],
                                capture_output=True, text=True, timeout=10,
                                encoding="utf-8", errors="replace")
            val = (os.path.normcase(os.path.realpath(rr.stdout.strip()))
                   if rr.returncode == 0 and rr.stdout.strip() else None)
            _GITDIR_CACHE[key] = val
            return val

        mine = _gitdir(path)
        if mine is None:
            return False          # git ran and said no. That is an authoritative answer.
        here = os.path.normcase(os.path.realpath(path))
        parent = os.path.dirname(os.path.realpath(path))
        theirs = _gitdir(parent) if parent and parent != os.path.realpath(path) else None
        if mine == theirs:
            return False          # same checkout as the parent: an ordinary subdirectory, or a
                                  # forgery whose invalid .git made git answer about the ancestor.
        # DIFFERENT-FROM-PARENT IS NECESSARY BUT NOT SUFFICIENT, and that was the seventh forgery:
        # a `.git` FILE may point at ANY real git-dir, including an unrelated repo's. git accepts it
        # -- that is exactly what a submodule pointer looks like -- so `mine != theirs` was True and
        # the subtree got pruned. `--show-toplevel` does not discriminate either; it returns the
        # directory itself in both cases. (s42 defect-hunter, round 7, confirmed empirically.)
        #
        # A GENUINE checkout's git-dir lives under one of exactly two places:
        #   * this directory      -- a nested clone (<dir>/.git)
        #   * the parent's git-dir -- a worktree or submodule OF THIS REPO
        #                             (<main>/.git/worktrees/<n>, <main>/.git/modules/<n>)
        # A pointer at a foreign repo is under neither.
        if mine == here or mine.startswith(here + os.sep):
            return True
        return bool(theirs) and mine.startswith(theirs + os.sep)
    except (OSError, subprocess.SubprocessError):
        pass
    # git unavailable: fail toward walking, never toward skipping.
    if os.path.isdir(marker):
        return any(os.path.isdir(os.path.join(marker, n)) for n in ("refs", "objects"))
    return False

def _prune(root, dirpath, dirnames):
    """Drop directories a guard must not descend into, in place.

    NESTED CHECKOUTS ARE THE IMPORTANT ONE. A git worktree or nested repo holds a DIFFERENT BRANCH's
    files, and any directory carrying its own `.git` (a dir for a nested repo, a FILE for a worktree)
    is one. Measured on dev-main 2026-07-31: the unpruned walk saw 85 .py files where the repo tracks
    22 -- the excess being two worktrees under .claude/worktrees/. Left unpruned, ci-lint-gate would
    compile another branch's source and fail THIS repo's PR for a defect that is not in it, and the
    python surface would be declared true on the strength of files git does not track here.
    (s42 evolution-auditor, which caught the stale count and with it the bug underneath.)
    """
    keep = []
    for d in dirnames:
        if d in (".git", "node_modules", "__pycache__", ".venv"):
            continue
        if _is_real_checkout(os.path.join(dirpath, d)):
            continue  # nested repo or worktree: a different branch's tree
        keep.append(d)
    dirnames[:] = keep


def read_caps(root):
    """Parse the flat manifest. Returns (dict, error_string_or_None).

    No PyYAML, because a guard should depend on as little as possible -- every dependency is one
    more thing that can be missing on the day the guard matters. (NOT because runners lack it: they
    have it, and an earlier draft asserted otherwise without measuring.) A value that is neither
    true nor false is an ERROR rather than a default -- a typo must not silently disarm a guard.
    """
    path = os.path.join(root, CAPS_REL)
    if not os.path.isfile(path):
        return None, "%s is missing. Every repo must declare its surfaces." % CAPS_REL
    caps = {}
    # utf-8-sig: a BOM is not whitespace, so it survives .strip() and stops line 1 being recognised
    # as a comment -- the parser then rejects the header as "not a key: value pair", which is a
    # fail-loud but actively misleading verdict. These files are authored on Windows and read on
    # Linux runners, so this is reachable. (s42 defect-hunter.)
    with open(path, encoding="utf-8-sig") as fh:
        for n, line in enumerate(fh, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            key, sep, val = s.partition(":")
            if not sep:
                return None, "%s:%d is not a key: value pair -- %r" % (CAPS_REL, n, s)
            key, val = key.strip(), val.strip()
            if val not in ("true", "false"):
                return None, ("%s:%d key %r has value %r; only true or false are legal. A typo "
                              "must not read as false and quietly disarm a guard."
                              % (CAPS_REL, n, key, val))
            if key in caps:
                return None, ("%s:%d declares %r twice. Last-wins would let a second line silently "
                              "override the first, which is the same quiet disarming a typo'd value "
                              "is rejected for." % (CAPS_REL, n, key))
            caps[key] = (val == "true")
    missing = [s for s in SURFACES if s not in caps]
    if missing:
        # DEFAULT TO false AND SAY SO LOUDLY -- do not hard-fail.
        #
        # This file is SEED (written once per repo, never overwritten) while the guard engine is
        # STRICT (re-pushed to all 12 repos on every sync). So the first time SURFACES gains a
        # member, every existing manifest lacks it -- and a hard failure here would turn EVERY PR in
        # ALL 12 REPOS red simultaneously, at the moment someone added one line to a baseline. A
        # guard that bricks the fleet to report its own upgrade is worse than the drift it detects.
        # (s42 future-proofing-auditor.)
        #
        # Defaulting to false is SAFE rather than lax, because the declaration is checked BOTH ways:
        # if the new surface is genuinely absent the repo passes, and if it is present the
        # undeclared-surface check fails exactly as it should. The default cannot hide a real
        # surface -- it only avoids punishing a repo for a key that did not exist when it was seeded.
        for k in missing:
            caps[k] = False
        out("::notice title=capability manifest needs a new key::%s does not declare %s; treating "
            "as false for now. Add %s to %s -- the check still fails if the surface is actually "
            "present." % (CAPS_REL, ", ".join(missing), ", ".join(missing), CAPS_REL))
    return caps, None


# WHERE A CODE GRAPH ACTUALLY LIVES. Both of these are real, in use, today:
#   infra/graphify/graph.json   tcp-supabase
#   graphify/graph.json         blog-production-engine -- a multi-megabyte graph. Re-derive any
#                               figure with `git cat-file -s <ref>:graphify/graph.json`, NOT with
#                               `wc -c` on the working copy. The blob is 2154320 bytes at every
#                               commit; a Windows checkout of that same blob reads 2215277,
#                               because core.autocrlf=true expands 60957 line endings to CRLF.
#                               Same file, same commit, two numbers.
#                                 CORRECTED 2026-08-01. An earlier version of this comment said
#                                 the figure "differs per branch" and told you to use `wc -c`.
#                                 That attributed a line-ending artifact to branch content, so
#                                 anyone following it on a different tree would have concluded
#                                 the graph had changed when nothing had. The advice to re-derive
#                                 was right; the method and the stated cause were both wrong.
# Only the first was ever checked. So BPE's detect() said absent, its
# repo-capabilities.yml declared graphify:false, the two agreed, and the pair passed
# through assert_surface()'s "declares none, none present -- PASS (no-op)" branch.
# That is a VACUOUS PASS: the undeclared-surface FAIL below is real code that works,
# it simply could never see the larger of the two graphs. The promise at
# repo-capabilities.yml ("declared false, present true = FAIL") did not hold, and the
# contamination check in check_graphify() never once ran on BPE's 2.2 MB graph.
#
# Held as ONE list consumed by BOTH detect() and check_graphify(), because those two
# previously hardcoded the same literal independently. Fixing only detect() would have
# made the surface DETECTED and still never CHECKED -- a quieter bug than the one being
# fixed, and harder to find. One source, two readers.
GRAPH_RELPATHS = (
    os.path.join("infra", "graphify", "graph.json"),
    os.path.join("graphify", "graph.json"),
)


def _graphify_graph(root):
    """Absolute path of this repo's code graph, or None if it has none. First match wins.

    GRAPH_RELPATHS is a FAST PATH, not the definition. The definition is "a graph.json inside a
    directory named graphify", found at any depth, and the walk below is what makes that true.

    The distinction is the whole finding. Widening one hardcoded path to a tuple of two fixes
    the two repos that exist today and reproduces the identical vacuous pass on repo #14, whose
    graph sits somewhere neither literal names: detect() says absent, the manifest says false,
    the two agree, and the contamination check never runs -- exactly the bug this function was
    added to kill, one instance further along. A list of known locations cannot close a defect
    class whose whole shape is "the location we did not know about".
    (s42 evolution-auditor, 2026-08-01.)

    COST, measured rather than assumed, because this walks where the old version did not. A repo
    WITH a graph never walks at all -- both real ones hit the fast path (blog-production-engine
    and tcp-supabase: 0.00s). A repo without one pays a full _prune-guarded walk: dev-main 0.22s,
    claude-chronicle 0.13s, idea-processor 0.01s. `check_graphify()` calls this after `detect()`
    already did, so a graph-less repo pays it twice -- worst case measured at well under half a
    second, and deliberately NOT memoised: a module-level cache would trade a measured non-problem
    for a staleness bug in a guard whose whole job is reading the tree as it is right now.
    (s42 defect-hunter flagged the double walk; the numbers are why it stays.)
    """
    for rel in GRAPH_RELPATHS:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            return p
    for dirpath, dirnames, filenames in os.walk(root):
        _prune(root, dirpath, dirnames)
        if os.path.basename(dirpath) == "graphify" and "graph.json" in filenames:
            return os.path.join(dirpath, "graph.json")
    return None


def detect(root, surface):
    """Is the surface actually present in this tree? Presence only, never the declaration."""
    j = os.path.join
    if surface == "tier0":
        d = j(root, "supabase", "migrations")
        return os.path.isdir(d) and any(f.endswith(".sql") for f in os.listdir(d))
    if surface == "edge_functions":
        d = j(root, "supabase", "functions")
        return os.path.isdir(d) and any(os.path.isdir(j(d, f)) for f in os.listdir(d))
    if surface == "graphify":
        return (_graphify_graph(root) is not None
                or os.path.isdir(j(root, "supabase", "functions", "graphify-ingest")))
    if surface == "node":
        return os.path.isfile(j(root, "package.json"))
    if surface == "python":
        # "has python SOURCE", not "has a python PACKAGE". Measured 2026-07-31: keying this on
        # requirements.txt / pyproject.toml made dev-main declare python:false while holding python
        # source it would never lint. A gate that is honest and useless is still useless. Widened
        # only after checking it breaks nothing: every repo holding .py compiles clean.
        # COUNTING RULE for any .py figure: this walk, after _prune() -- which drops nested
        # checkouts. dev-main is 22 pruned; the unpruned walk said 85, the excess being two
        # worktrees holding other branches. A count without its rule is not a measurement.
        if os.path.isfile(j(root, "requirements.txt")) or os.path.isfile(j(root, "pyproject.toml")):
            return True
        guards = os.path.normpath(j(root, ".github", "guards"))
        for dirpath, dirnames, filenames in os.walk(root):
            _prune(root, dirpath, dirnames)
            # THIS GUARD IS NOT A PYTHON SURFACE. Without this exclusion, syncing repo-guard.py into
            # a repo makes that repo declare python:true -- so the flag would read `true` in all 12
            # by construction, carry no information, and make the undeclared-surface check for
            # python incapable of ever firing. A capability manifest describes the REPOSITORY, not
            # the scaffolding installed to check it. (Found by running the sync: all 12 manifests
            # flipped to python:true at once, which is the shape of a measurement measuring itself.)
            if os.path.normpath(dirpath) == guards:
                continue
            if any(f.endswith(".py") for f in filenames):
                return True
        return False
    raise ValueError(surface)


def assert_surface(root, caps, surface):
    """The four-way truth table. Returns (rc, should_run_deeper_check)."""
    declared, present = caps[surface], detect(root, surface)
    if declared and present:
        out("%s: declared and present -- running the real check." % surface)
        return 0, True  # every surface that reaches here HAS a deeper check; see CHECKS + capabilities
    if not declared and not present:
        out("%s: this repo declares no %s surface, and none is present. PASS (no-op)."
            % (surface, surface))
        return 0, False
    if not declared and present:
        return fail("undeclared surface",
                    "%s exists in this tree but %s declares it false. Declare it (and the guard "
                    "will start checking it), or remove it. A surface nobody declared is a surface "
                    "nobody guards." % (surface, CAPS_REL)), False
    return fail("phantom declaration",
                "%s declares %s true but no such surface is present. Either the declaration is "
                "stale or something was deleted. A guard that cannot find its subject is not a "
                "guard." % (CAPS_REL, surface)), False


# -------------------------------------------------------------------------------------------------
# checks
# -------------------------------------------------------------------------------------------------
def check_edge_functions(root, caps):
    """Assert every declared Edge Function directory actually holds an entrypoint.

    Added after the s35 reviewer found that `edge_functions` was the one surface with NO deeper
    check anywhere, while assert_surface() printed "running the real check" for it -- an untrue
    line in the guard's own output. Either the message or the check had to change; the check is
    the more useful half. A function directory with no index.ts deploys to nothing.
    """
    rc, run = assert_surface(root, caps, "edge_functions")
    if rc or not run:
        return rc
    d = os.path.join(root, "supabase", "functions")
    bad = [f for f in sorted(os.listdir(d))
           if os.path.isdir(os.path.join(d, f)) and not f.startswith("_")
           and not os.path.isfile(os.path.join(d, f, "index.ts"))]
    if bad:
        return fail("edge function without an entrypoint",
                    "these declare a function directory with no index.ts, so they deploy to "
                    "nothing: " + ", ".join(bad))
    out("edge_functions: every function directory has an index.ts. PASS.")
    return 0


def check_capabilities(root, caps):
    """Every surface, both directions, plus the surface-specific assertions.

    This gate is the one that keeps the others honest, so it also runs the deeper check for any
    surface that does not have a dedicated job of its own.
    """
    rc = 0
    for s in SURFACES:
        r, _ = assert_surface(root, caps, s)
        rc |= r
    if rc == 0:
        rc |= check_edge_functions(root, caps)
    if rc == 0:
        out("capability-gate: all %d declarations match the tree. PASS." % len(SURFACES))
    return rc


def check_tier0(root, caps):
    rc, run = assert_surface(root, caps, "tier0")
    if rc or not run:
        return rc
    d = os.path.join(root, "supabase", "migrations")
    bad = []
    for f in sorted(os.listdir(d)):
        if not f.endswith(".sql"):
            continue
        if os.path.getsize(os.path.join(d, f)) == 0:
            bad.append("%s is EMPTY" % f)
        elif not re.match(r"^\d{14}_", f):
            bad.append("%s lacks a 14-digit timestamp prefix" % f)
    if bad:
        return fail("tier-0 migration defect",
                    "a migration is immutable once applied, so a malformed one cannot be renamed "
                    "later: " + "; ".join(bad))
    out("tier0: every migration is non-empty and timestamp-prefixed. PASS.")
    return 0


def check_lint(root, caps):
    rc_n, run_n = assert_surface(root, caps, "node")
    rc_p, run_p = assert_surface(root, caps, "python")
    rc = rc_n | rc_p
    if rc:
        return rc
    if not run_n and not run_p:
        out("ci-lint-gate: this repo declares neither a node nor a python surface. PASS (no-op).")
        return 0
    if run_n:
        p = os.path.join(root, "package.json")
        try:
            with open(p, encoding="utf-8") as fh:
                json.load(fh)
        except Exception as exc:
            return fail("package.json invalid", "%s does not parse: %s" % (p, exc))
        out("ci-lint-gate: package.json parses.")
    if run_p:
        bad = []
        for dirpath, dirnames, filenames in os.walk(root):
            _prune(root, dirpath, dirnames)
            for f in filenames:
                if not f.endswith(".py"):
                    continue
                fp = os.path.join(dirpath, f)
                try:
                    with open(fp, encoding="utf-8") as fh:
                        compile(fh.read(), fp, "exec")
                except SyntaxError as exc:
                    bad.append("%s: %s" % (os.path.relpath(fp, root), exc))
        if bad:
            return fail("python syntax error", "; ".join(bad[:10]))
        out("ci-lint-gate: every .py file compiles.")
    return 0


def check_graphify(root, caps):
    rc, run = assert_surface(root, caps, "graphify")
    if rc or not run:
        return rc
    ef = os.path.join(root, "supabase", "functions", "graphify-ingest", "index.ts")
    if os.path.isfile(ef):
        with open(ef, encoding="utf-8", errors="replace") as fh:
            m = re.search(r"^const GRAPH_PATH = \"(.*)\";$", fh.read(), re.M)
        if not m:
            return fail("GRAPH_PATH unreadable",
                        "could not parse the GRAPH_PATH constant out of %s. If the declaration was "
                        "reshaped, update this guard in the same PR -- a guard that cannot read "
                        "its target is not a guard." % ef)
        if not os.path.isfile(os.path.join(root, m.group(1))):
            return fail("GRAPH_PATH does not resolve",
                        "graphify-ingest fetches %r from the default branch at runtime, but no such "
                        "file exists at HEAD. Merging this would 404 the daily code-graph reload."
                        % m.group(1))
        out("graphify: GRAPH_PATH resolves to a file present at HEAD.")
    gj = _graphify_graph(root)
    if not os.path.isfile(ef) and gj is None:
        # detect() calls the surface present on DIRECTORY existence, so a bare empty
        # supabase/functions/graphify-ingest/ reached here and fell through to `return 0` having
        # asserted nothing at all -- a PASS that verified nothing. Found by the s35 reviewer.
        return fail("graphify surface has nothing to check",
                    "graphify is declared and detected, but neither "
                    "supabase/functions/graphify-ingest/index.ts nor any of %s "
                    "exists. A guard that cannot find its subject is not a guard."
                    % ", ".join(GRAPH_RELPATHS))
    if gj is not None:
        rel = os.path.relpath(gj, root)
        with open(gj, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        if re.search(r"\"file_type\"\s*:\s*\"concept\"|\"commit:|local_proxy|ON_BRANCH|PARENT_OF",
                     body):
            return fail("graph contamination",
                        "%s carries git-history / non-code artifacts. "
                        "Violates DNA invariant 3 (code-only). Regenerate git-free." % rel)
        out("graphify: %s is code-only." % rel)
    return 0


def _uses_refs(body):
    """Every `uses:` value in a workflow or composite action. Returns (refs, parsed_structurally).

    PARSE FIRST, REGEX ONLY AS A FALLBACK. The original was a line-anchored regex, which cannot see
    flow-style YAML -- `steps: [ { uses: "foo/bar@v6" } ]` on a single line, or a value supplied
    through a YAML anchor/alias. An unpinned third-party action written that way reported PASS, and
    a security check that can be stepped around is worse than none, because it reads as coverage.
    (s36 security-reviewer, recorded as boundary B-2 and now closed.)

    PyYAML is present on ubuntu-latest -- tcp-supabase's own workflow-diff-gate calls yaml.safe_load
    there and passes. But this guard must not HARD-DEPEND on it: if the import fails, or the file
    will not parse, falling back to the regex is strictly better than reporting a clean pass on a
    file nobody read. The fallback is ANNOUNCED through the second return value, never silent --
    reduced coverage must not look identical to full coverage.
    """
    refs = []
    try:
        import yaml
        parsed = yaml.safe_load(body)
    except Exception:
        parsed = None

    if isinstance(parsed, (dict, list)):
        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "uses" and isinstance(v, str):
                        refs.append(v.strip())
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(parsed)
        return refs, True

    for m in re.finditer(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", body, re.M):
        refs.append(m.group(1).strip().strip("'").strip('"'))
    return refs, False


def check_security(root, caps):
    """Supply-chain assertions over the workflow surface. Universal and SECRETLESS.

    This REPLACES tcp-supabase's tcp-security-guardian rather than narrowing it. That guard needs
    four secrets including a Groq API key for an LLM review, none of which exist in an app repo.
    Hindsight de43f3d9 is explicit that when a deterministic scanner rule cannot hold, you RETIRE
    the rule rather than scope-patch it into a narrow shape still claiming to be the same check. So
    the TCP-0xx rule ids are gone, and what stands are two assertions needing no secret at all.
    """
    wf = os.path.join(root, ".github", "workflows")
    acts = os.path.join(root, ".github", "actions")
    targets = []
    if os.path.isdir(wf):
        for f in sorted(os.listdir(wf)):
            if f.endswith((".yml", ".yaml")):
                targets.append((f, os.path.join(wf, f)))
    # COMPOSITE ACTIONS TOO. A local `uses: ./.github/actions/foo` is correctly skipped below as
    # first-party, but the third-party `uses:` lines INSIDE foo/action.yml are just as dangerous and
    # were invisible until this walk existed -- an unpinned action one level down is still an
    # unpinned action running with your token.
    if os.path.isdir(acts):
        for dirpath, _dirnames, filenames in os.walk(acts):
            for f in filenames:
                if f in ("action.yml", "action.yaml"):
                    targets.append((os.path.relpath(os.path.join(dirpath, f), root),
                                    os.path.join(dirpath, f)))
    if not targets:
        out("repo-security-guardian: no workflow or composite-action files. PASS (no-op).")
        return 0
    unpinned, prt, unparsed = [], [], []
    sha40 = re.compile(r"^[0-9a-f]{40}$")
    for f, path in targets:
        with open(path, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        refs, structured = _uses_refs(body)
        if not structured:
            unparsed.append(f)
        for ref in refs:
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if any(ref.startswith(fp) for fp in FIRST_PARTY):
                continue
            if "@" not in ref or not sha40.match(ref.rsplit("@", 1)[1]):
                unpinned.append("%s -> %s" % (f, ref))
        # pull_request_target that reaches the PR's own head runs UNTRUSTED fork code with a
        # write-scoped token and repo secrets. The highest-severity defect in Actions.
        #
        # THE FIRST VERSION OF THIS CHECK WAS EVADABLE BY A ONE-LINE CHANGE, and a security check
        # that can be stepped around is worse than none, because it reads as coverage. It required
        # the expression to sit IMMEDIATELY after `ref:`, so both of these walked straight past it:
        #   env: {HEAD: <expr>}  then  with: {ref: <env ref>}     -- indirection through env
        #   run: git fetch origin pull/<num>/head:pr && git checkout pr  -- no `ref:` key at all
        # Now: under pull_request_target, ANY mention of the PR head expression anywhere in the
        # file, and any explicit fetch of the pull/N/head ref, is a finding. This over-matches
        # rather than under-matches on purpose -- a false positive costs a conversation, a false
        # negative costs the repository.
        if "pull_request_target" in body:
            if (re.search(r"github\.event\.pull_request\.head", body)
                    or re.search(r"pull/[^\s]*/head", body)
                    or re.search(r"refs/pull/", body)):
                prt.append(f)
    rc = 0
    if unpinned:
        rc |= fail("third-party action not sha-pinned",
                   "a tag is mutable -- v6 can be repointed at new code by whoever controls the "
                   "action, and your workflow then runs it with your token: " + "; ".join(unpinned))
    if prt:
        rc |= fail("pull_request_target checks out PR head",
                   "this runs untrusted fork code with a write-scoped token and repo secrets: "
                   + "; ".join(prt))
    if unparsed:
        # NEVER SILENT. A file the parser could not read was checked by the WEAKER fallback,
        # and the reader must be told which -- reduced coverage must not look identical to
        # full coverage.
        out("::notice title=fell back to regex scanning::%s could not be parsed as YAML; "
            "scanned with the line-anchored fallback, which cannot see flow-style uses:."
            % ", ".join(unparsed))
    if rc == 0:
        out("repo-security-guardian: third-party actions sha-pinned; no pull_request_target head "
            "checkout. PASS.")
    return rc


def check_automerge(root, caps, event_path=None):
    """FAIL if this PR is set to merge itself.

    tcp-supabase's auto-merge-mirror is deliberately NOT ported: it auto-merges, the exact opposite
    of the requirement that a human understand what becomes permanent BEFORE it does. Omitting it
    would leave the behaviour merely absent; this makes it DETECTED, so enabling auto-merge anywhere
    becomes a red check rather than a quiet merge.
    """
    ep = event_path or os.environ.get("GITHUB_EVENT_PATH")
    if not ep or not os.path.isfile(ep):
        out("block-automerge: no event payload (not a PR run). PASS (no-op).")
        return 0
    try:
        with open(ep, encoding="utf-8") as fh:
            ev = json.load(fh)
    except Exception as exc:
        out("::error title=event payload unreadable::%s" % exc)
        return 2
    pr = ev.get("pull_request") or {}
    labels = [(lb.get("name") or "").lower() for lb in (pr.get("labels") or [])]
    hits = []
    if pr.get("auto_merge"):
        hits.append("GitHub auto-merge is ENABLED on this PR")
    for bad in ("automerge", "auto-merge"):
        if bad in labels:
            hits.append("PR carries the %s label" % bad)
    if hits:
        return fail("auto-merge is not permitted",
                    "; ".join(hits) + ". A merge to the default branch is a one-way door and needs "
                    "an explicit human yes (CLAUDE.md sections 0, 7, 10). Disable auto-merge.")
    out("block-automerge: auto-merge is not enabled and no automerge label. PASS.")
    return 0


def integrity_verdict(absent, changed):
    """Decide the guard-integrity outcome. PURE -- no git, no network, so it is directly testable.

    THE SHELL WAS THE ONLY UNTESTED THING IN THE SUITE, and it was the job that closes B-1.
    `repo-guards.yml` states the principle four lines above it: guard logic written inline in a
    `run:` block "can only be exercised by pushing to CI, which makes its must-fire control
    something you assert rather than run". Every other job obeys that by delegating to this script;
    guard-integrity did not. Both the s42 devops-auditor and future-proofing-auditor caught the
    contradiction in round 3, independently.

    So the shell now does only what shell must do -- ask git which files differ -- and hands the
    DECISION here, where it has controls in both directions.

      absent  : STRICT paths not present on the base branch (first adoption -- not tampering)
      changed : STRICT paths that differ from the base branch (a human must look)

    Returns (rc, lines_to_print).
    """
    out = []
    if absent:
        out.append("::notice title=first adoption::not yet on the base branch, nothing to "
                   "compare: " + " ".join(sorted(absent)))
    if changed:
        out.append(
            "::error title=a STRICT guard file was modified in this PR::"
            + " ".join(sorted(changed))
            + " -- these are synced from dev-main and their only editable source is there. If this "
              "IS the sync landing a reviewed change, that is what it looks like, and a human "
              "should read the diff before merging. If it is not, the guard was edited in the repo "
              "it guards.")
        return 1, out
    out.append("guard-integrity: every STRICT guard file matches the base branch. PASS.")
    return 0, out


CHECKS = {
    "capabilities": check_capabilities,
    "tier0": check_tier0,
    "lint": check_lint,
    "security": check_security,
    "graphify": check_graphify,
    "automerge": check_automerge,
}


# -------------------------------------------------------------------------------------------------
# selftest -- BOTH directions for every check
# -------------------------------------------------------------------------------------------------
ALL_FALSE = "tier0: false\nedge_functions: false\ngraphify: false\nnode: false\npython: false\n"

# Built by concatenation so this source file never contains a literal Actions expression: the guard
# is itself scanned by actionlint and by its own security check, and a bare expression here reads as
# a workflow fragment to anything grepping for one.
_HEAD_REF = "          ref: $" + "{{ github.event.pull_request.head.sha }}\n"

_PRT_ENV = ('on:\n  pull_request_target:\njobs:\n  x:\n    env:\n      HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env.HEAD_SHA }}\n')
_PRT_FETCH = ('on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: git fetch origin pull/7/head:pr && git checkout pr\n')
_COMP_BAD = ('runs:\n  using: composite\n  steps:\n    - uses: evil/thing@v1\n')
_EF_OK = 'export default 1;\n'
# B-2: flow-style YAML, invisible to the old line-anchored regex
_FLOW_BAD = 'jobs: { x: { steps: [ { uses: "evil/thing@v6" } ] } }\n'
_FLOW_OK = 'jobs: { x: { steps: [ { uses: "evil/thing@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } ] } }\n'
_ANCHOR_BAD = 'x: &a\n  uses: evil/thing@v6\njobs:\n  j:\n    steps:\n      - *a\n'
_COMP_OK = ('runs:\n  using: composite\n  steps:\n    - uses: evil/thing@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')


def _flip(key, value="true"):
    return ALL_FALSE.replace("%s: false" % key, "%s: %s" % (key, value))


GIT_INIT = "<GIT-INIT>"   # fixture sentinel: make this directory a REAL git repo
GIT_WORKTREE = "<GIT-WORKTREE>"  # fixture sentinel: make this a REAL LINKED WORKTREE
GIT_FOREIGN = "<GIT-FOREIGN>"    # fixture sentinel: a .git file pointing at an UNRELATED repo
# A linked worktree is the shape no fixture covered, and the shape a containment check
# wrongly rejected: its git-dir lives under the MAIN repo, never under the worktree. It has
# to be built by git, not fabricated, or the control tests something git would not accept.


def _mktree(base, caps_text, files):
    os.makedirs(os.path.join(base, ".github"), exist_ok=True)
    if caps_text is not None:
        with open(os.path.join(base, CAPS_REL), "w", encoding="utf-8") as fh:
            fh.write(caps_text)
    for rel, body in files.items():
        p = os.path.join(base, rel.replace("/", os.sep))
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        if body == GIT_FOREIGN:
            # The seventh forgery: a pointer at a REAL but unrelated repo. git accepts it -- that
            # is what a submodule pointer looks like -- so 'different from parent' alone was not
            # enough. Built with a real outside repo, since a fake target git would reject proves
            # nothing about this case.
            foreign = tempfile.mkdtemp(prefix='repo-guard-foreign-')
            subprocess.run(['git', 'init', '-q', foreign], capture_output=True, timeout=20)
            os.makedirs(d, exist_ok=True)
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write('gitdir: ' + os.path.join(foreign, '.git').replace(chr(92), '/') + chr(10))
            continue
        if body == GIT_WORKTREE:
            subprocess.run(["git", "-C", base, "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-q", "--allow-empty", "-m", "seed"],
                           capture_output=True, timeout=20)
            subprocess.run(["git", "-C", base, "worktree", "add", "-q", "--detach", d],
                           capture_output=True, timeout=30)
            continue
        if body == GIT_INIT:
            # A REAL repository, because the guard now asks git and git is not fooled by a fixture.
            # The positive controls got STRONGER when the heuristic was replaced: they used to
            # assert that a fabricated `.git` counted as a checkout, which was the bug.
            os.makedirs(d, exist_ok=True)
            subprocess.run(["git", "init", "-q", d], capture_output=True, timeout=20)
            continue
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)



def _cases():
    """(name, expected_rc, expected_error_title, caps_text, files, check).

    EXPECTED_ERROR_TITLE IS NOT DECORATION. An earlier version of this selftest collapsed the return
    code to pass/fail, and a deliberate sabotage -- deleting the `not declared and present` branch --
    STILL PASSED every case, because the undeclared-surface tree then fell through to the
    phantom-declaration failure and returned 1 either way. The case bound "did it fail", the
    behaviour took a different path, and the control never noticed. Asserting WHICH failure is what
    makes a red test mean the thing it claims.
    """
    sha = "a" * 40
    return [
        # --- the truth table, all four corners ---------------------------------------------------
        ("truth table: declared none + none present -> PASS", 0, None, ALL_FALSE, {}, "capabilities"),
        ("truth table: UNDECLARED surface present -> FAIL", 1, "undeclared surface", ALL_FALSE,
         {"package.json": "{}"}, "capabilities"),
        ("truth table: declared + present -> PASS", 0, None, _flip("node"),
         {"package.json": "{}"}, "capabilities"),
        ("truth table: PHANTOM declaration -> FAIL", 1, "phantom declaration", _flip("node"),
         {}, "capabilities"),

        # --- manifest integrity: a broken manifest must never read as all-false ------------------
        ("manifest missing -> FAIL", 1, "is missing", None, {}, "capabilities"),
        ("manifest typo value (FALSE) -> FAIL, never silently false", 1, "only true or false",
         "tier0: FALSE\nedge_functions: false\ngraphify: false\nnode: false\npython: false\n",
         {}, "capabilities"),
        # An INCOMPLETE manifest defaults the missing keys to false and says so, rather than hard
        # failing -- otherwise adding one line to the canonical baseline would red every PR in all
        # 12 repos at once (the manifest is SEED, the engine is STRICT). BOTH directions matter:
        ("manifest incomplete, missing surface ABSENT -> PASS with a notice", 0, None,
         "tier0: false\n", {}, "capabilities"),
        ("manifest incomplete, missing surface PRESENT -> still FAIL", 1, "undeclared surface",
         "tier0: false\n", {"package.json": "{}"}, "capabilities"),
        ("manifest declares a key TWICE -> FAIL, never last-wins", 1, "twice",
         "tier0: false\ntier0: true\nedge_functions: false\ngraphify: false\nnode: false\npython: false\n", {}, "capabilities"),

        # --- tier0 -------------------------------------------------------------------------------
        ("tier0 undeclared, no migrations -> PASS", 0, None, ALL_FALSE, {}, "tier0"),
        ("tier0 declared, good migration -> PASS", 0, None, _flip("tier0"),
         {"supabase/migrations/20260731120000_x.sql": "select 1;"}, "tier0"),
        ("tier0 declared, EMPTY migration -> FAIL", 1, "tier-0 migration defect", _flip("tier0"),
         {"supabase/migrations/20260731120000_x.sql": ""}, "tier0"),
        ("tier0 declared, unprefixed migration -> FAIL", 1, "tier-0 migration defect",
         _flip("tier0"), {"supabase/migrations/oops.sql": "select 1;"}, "tier0"),

        # --- lint --------------------------------------------------------------------------------
        ("lint: no language surface -> PASS (no-op)", 0, None, ALL_FALSE, {}, "lint"),
        ("lint: node declared, valid package.json -> PASS", 0, None, _flip("node"),
         {"package.json": "{\"a\": 1}"}, "lint"),
        ("lint: node declared, BROKEN package.json -> FAIL", 1, "package.json invalid",
         _flip("node"), {"package.json": "{nope"}, "lint"),
        ("lint: python declared, BROKEN .py -> FAIL", 1, "python syntax error", _flip("python"),
         {"requirements.txt": "", "b.py": "def ("}, "lint"),
        ("lint: python declared, valid .py -> PASS", 0, None, _flip("python"),
         {"requirements.txt": "", "b.py": "x = 1\n"}, "lint"),
        # the widened detection: a bare .py with NO package manifest is still a python surface
        ("lint: python declared via bare .py, no manifest -> PASS", 0, None, _flip("python"),
         {"b.py": "x = 1"}, "lint"),
        ("truth table: bare .py present but python undeclared -> FAIL", 1, "undeclared surface",
         ALL_FALSE, {"b.py": "x = 1"}, "capabilities"),
        # ROUND 7: a `.git` FILE may point at ANY real git-dir, including an UNRELATED repo's.
        # git accepts it, so 'different from the parent' was true and the subtree was pruned.
        ("lint: a `.git` pointing at a FOREIGN repo is not this repo's checkout", 1,
         "python syntax error", _flip("python"), {"evil/.git": GIT_FOREIGN, "evil/broken.py": "def ("},
         "lint"),
        # THE REGRESSION ROUND 6's OWN FIX INTRODUCED: a linked worktree's git-dir lives under the
        # MAIN repo (.git/worktrees/<name>), never under the worktree -- so requiring containment
        # rejected every real worktree and the walk re-entered them. Built by git, not fabricated.
        ("lint: a REAL LINKED WORKTREE is a checkout and must be skipped", 0, None,
         _flip("python"), {"wt3/.git": GIT_WORKTREE, "wt3/broken.py": "def (", "ok.py": "x = 1"},
         "lint"),
        # ROUND 6, and the cheapest of all: a `.git` DIRECTORY holding one file. It fails git's own
        # local validation, so git's discovery walks UP and answers about the ANCESTOR repo with
        # rc=0 -- and a naive exit-code check then prunes the subtree. Only fires when the fixture
        # base is itself a repo, which it now is.
        ("lint: a forged `.git` dir NESTED IN A REAL REPO must not prune the subtree", 1,
         "python syntax error", _flip("python"), {"evil/.git/config": "[core]", "evil/broken.py": "def ("}, "lint"),
        # ROUND 5, the two cheapest forgeries yet: `gitdir: .` resolves to the containing directory
        # (always present), and an EMPTY config satisfied an existence-only corroboration check.
        ("lint: `gitdir: .` self-certifying a directory -> not a checkout", 1,
         "python syntax error", _flip("python"), {"evil/.git": "gitdir: .", "evil/broken.py": "def ("}, "lint"),
        ("lint: an EMPTY .git/config is not corroboration -> not a checkout", 1,
         "python syntax error", _flip("python"), {"evil/.git/HEAD": "ref: refs/heads/main", "evil/.git/config": "", "evil/broken.py": "def ("}, "lint"),
        ("lint: a real worktree pointer (target holds HEAD) IS a checkout", 0, None,
         _flip("python"), {"wt2/.git": GIT_INIT, "wt2/broken.py": "def (", "ok.py": "x = 1"}, "lint"),
        # ROUND 4: a marker that merely LOOKS right but resolves to NOTHING is not a checkout.
        # `gitdir: nope` and a lone `.git/HEAD` both passed the round-3 test. (s42 defect-hunter.)
        ("lint: `.git` file whose gitdir target does NOT exist -> not a checkout", 1,
         "python syntax error", _flip("python"), {"evil/.git": "gitdir: nowhere-at-all", "evil/broken.py": "def ("}, "lint"),
        ("lint: `.git` dir with a plausible HEAD but nothing else -> not a checkout", 1,
         "python syntax error", _flip("python"), {"evil/.git/HEAD": "ref: refs/heads/main", "evil/broken.py": "def ("}, "lint"),
        ("lint: a CORROBORATED .git dir IS a checkout and is skipped", 0, None,
         _flip("python"), {"evil/.git": GIT_INIT, "evil/broken.py": "def (", "ok.py": "x = 1"}, "lint"),
        # THE EVASION: an EMPTY file called .git is not a checkout. The bare existence check let a
        # PR drop `evil/.git` beside broken code and skip the whole subtree. (s42 defect-hunter.)
        ("lint: a FAKE .git (empty file) must NOT hide a broken .py", 1, "python syntax error",
         _flip("python"), {"evil/.git": "", "evil/broken.py": "def ("}, "lint"),
        ("lint: a .git/HEAD that is EMPTY is not a checkout", 1, "python syntax error",
         _flip("python"), {"evil/.git/HEAD": "", "evil/broken.py": "def ("}, "lint"),
        # (A round-3 case asserting that a lone `.git/HEAD` IS a checkout lived here. It was
        # certifying exactly the fabrication round 4 closed, so it is gone rather than adjusted --
        # the CORROBORATED case above is its honest replacement.)
        ("lint: a .git DIRECTORY without HEAD is not a checkout either", 1, "python syntax error",
         _flip("python"), {"evil/.git/notes.txt": "x", "evil/broken.py": "def ("}, "lint"),
        # a nested checkout (worktree / nested repo) holds ANOTHER BRANCH's files and must not
        # count as this repo's surface, nor be linted as this repo's code
        ("truth table: .py inside a nested checkout -> NOT this repo's python surface", 0, None,
         ALL_FALSE, {"wt/.git": GIT_INIT, "wt/other.py": "def ("}, "capabilities"),
        ("lint: a BROKEN .py inside a nested checkout is not linted -> PASS", 0, None,
         ALL_FALSE, {"wt/.git": GIT_INIT, "wt/other.py": "def ("}, "lint"),
        # the self-reference control: installing this guard must not make a repo a python surface
        ("truth table: ONLY .github/guards/repo-guard.py present -> still no python surface",
         0, None, ALL_FALSE, {".github/guards/repo-guard.py": "x = 1"}, "capabilities"),

        # --- security ----------------------------------------------------------------------------
        ("security: sha-pinned third party -> PASS", 0, None, ALL_FALSE,
         {".github/workflows/a.yml":
          "jobs:\n  x:\n    steps:\n      - uses: foo/bar@" + sha + "\n"}, "security"),
        ("security: TAG-pinned third party -> FAIL", 1, "not sha-pinned", ALL_FALSE,
         {".github/workflows/a.yml": "jobs:\n  x:\n    steps:\n      - uses: foo/bar@v6\n"},
         "security"),
        ("security: actions/* unpinned is tolerated -> PASS", 0, None, ALL_FALSE,
         {".github/workflows/a.yml":
          "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"}, "security"),
        ("security: pull_request_target + head checkout -> FAIL", 1, "checks out PR head",
         ALL_FALSE, {".github/workflows/a.yml":
                     "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n"
                     "      - uses: actions/checkout@v4\n        with:\n" + _HEAD_REF}, "security"),
        ("security: pull_request_target WITHOUT head checkout -> PASS", 0, None, ALL_FALSE,
         {".github/workflows/a.yml":
          "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n"
          "      - uses: actions/checkout@v4\n"}, "security"),
        # THE TWO EVASIONS THAT WALKED PAST THE FIRST VERSION OF THIS CHECK, both reported by
        # the s36 security reviewer and both a one-line change from the case above.
        ("security: prt + head expr via ENV INDIRECTION -> FAIL", 1, "checks out PR head",
         ALL_FALSE, {".github/workflows/a.yml": _PRT_ENV}, "security"),
        ("security: prt + git fetch of pull/N/head, no ref: key at all -> FAIL", 1,
         "checks out PR head", ALL_FALSE, {".github/workflows/a.yml": _PRT_FETCH}, "security"),
        # a third-party action left unpinned INSIDE a local composite action, one level down
        ("security: unpinned third party inside .github/actions composite -> FAIL", 1,
         "not sha-pinned", ALL_FALSE, {".github/actions/foo/action.yml": _COMP_BAD}, "security"),
        ("security: sha-pinned inside composite -> PASS", 0, None, ALL_FALSE,
         {".github/actions/foo/action.yml": _COMP_OK}, "security"),
        # B-2 CLOSED: flow-style YAML was invisible to the line-anchored regex, so a tag-pinned
        # third-party action written on one line reported PASS.
        ("security: FLOW-STYLE tag-pinned third party -> FAIL", 1, "not sha-pinned",
         ALL_FALSE, {".github/workflows/a.yml": _FLOW_BAD}, "security"),
        ("security: flow-style SHA-pinned -> PASS", 0, None, ALL_FALSE,
         {".github/workflows/a.yml": _FLOW_OK}, "security"),
        ("security: tag-pinned via a YAML ANCHOR/ALIAS -> FAIL", 1, "not sha-pinned",
         ALL_FALSE, {".github/workflows/a.yml": _ANCHOR_BAD}, "security"),
        # edge_functions -- the surface that had NO deeper check until the s35 reviewer found the
        # guard printing "running the real check" for it anyway
        ("edge_functions undeclared + absent -> PASS", 0, None, ALL_FALSE, {}, "capabilities"),
        ("edge_functions declared, function has index.ts -> PASS", 0, None,
         _flip("edge_functions"), {"supabase/functions/hello/index.ts": _EF_OK}, "capabilities"),
        ("edge_functions declared, function dir with NO index.ts -> FAIL", 1,
         "without an entrypoint", _flip("edge_functions"),
         {"supabase/functions/hello/notes.md": "x"}, "capabilities"),
        # graphify declared+present but nothing verifiable -- previously a silent PASS
        ("graphify declared, bare empty graphify-ingest dir -> FAIL", 1, "nothing to check",
         _flip("graphify"), {"supabase/functions/graphify-ingest/notes.md": "x"}, "graphify"),

        # --- graphify ----------------------------------------------------------------------------
        ("graphify undeclared + absent -> PASS "
         "(the case that would BLOCK EVERY PR if ported unchanged)", 0, None, ALL_FALSE,
         {}, "graphify"),
        ("graphify declared, clean graph -> PASS", 0, None, _flip("graphify"),
         {"infra/graphify/graph.json": "{\"nodes\": []}"}, "graphify"),
        ("graphify declared, CONTAMINATED graph -> FAIL", 1, "graph contamination",
         _flip("graphify"), {"infra/graphify/graph.json": "{\"id\": \"commit:abc\"}"}, "graphify"),
        ("graphify declared, GRAPH_PATH dangling -> FAIL", 1, "does not resolve", _flip("graphify"),
         {"supabase/functions/graphify-ingest/index.ts":
          "const GRAPH_PATH = \"infra/graphify/graph.json\";\n"}, "graphify"),

        # --- graphify: the root-level graph path, and the vacuous pass it used to produce -------
        # Added 2026-08-01. detect() and check_graphify() both hardcoded infra/graphify/graph.json,
        # so a repo keeping its graph at graphify/graph.json (blog-production-engine, 2.2 MB) was
        # invisible to BOTH. Declared false, detected absent, agreed, PASS -- while the file sat
        # there unchecked. The first case below is the MUST-FIRE control: it is exactly the BPE
        # shape, and against the pre-fix guard it returned 0.
        ("MUST-FIRE: root-level graphify/graph.json present but declared FALSE -> FAIL "
         "(the BPE shape; passed vacuously before 2026-08-01)", 1, "undeclared surface", ALL_FALSE,
         {"graphify/graph.json": "{\"nodes\": []}"}, "graphify"),
        # MUST-FIRE for the ORIGINAL path too. Nothing ever proved the undeclared-surface branch
        # fires for infra/ either -- it was only ever exercised in its declared+present form.
        ("MUST-FIRE: infra/graphify/graph.json present but declared FALSE -> FAIL", 1,
         "undeclared surface", ALL_FALSE,
         {"infra/graphify/graph.json": "{\"nodes\": []}"}, "graphify"),
        # Detected is not the same as CHECKED. These two prove check_graphify() actually reads the
        # root-level path -- fixing detect() alone would have passed the case above and still never
        # opened the file, which is the quieter half of the same bug.
        ("graphify declared, clean graph at root-level graphify/ -> PASS", 0, None,
         _flip("graphify"), {"graphify/graph.json": "{\"nodes\": []}"}, "graphify"),
        ("graphify declared, CONTAMINATED graph at root-level graphify/ -> FAIL", 1,
         "graph contamination", _flip("graphify"),
         {"graphify/graph.json": "{\"id\": \"commit:abc\"}"}, "graphify"),

        # --- the location NOBODY put in the list ------------------------------------------------
        # These are the cases that distinguish "we widened the hardcoding" from "we closed the
        # class". Both use a path in neither GRAPH_RELPATHS entry. Against a list-only
        # implementation the first of them returns 0 -- the same vacuous pass, one repo further
        # along. (s42 evolution-auditor, 2026-08-01.)
        ("MUST-FIRE: graph at an UNLISTED location (tools/graphify/) present but declared "
         "FALSE -> FAIL", 1, "undeclared surface", ALL_FALSE,
         {"tools/graphify/graph.json": "{\"nodes\": []}"}, "graphify"),
        ("graphify declared, CONTAMINATED graph at an UNLISTED location -> FAIL "
         "(proves the walk feeds the contamination check, not just detection)", 1,
         "graph contamination", _flip("graphify"),
         {"tools/graphify/graph.json": "{\"id\": \"commit:abc\"}"}, "graphify"),
        # MUST-STAY-SILENT for the walk: a graph.json NOT inside a graphify/ directory, and a
        # graphify/ directory with no graph.json, are both absent. Without these the walk could
        # match anything called graph.json and nothing would notice.
        ("graph.json outside any graphify/ dir -> still ABSENT, PASS (no-op)", 0, None,
         ALL_FALSE, {"data/graph.json": "{\"nodes\": []}"}, "graphify"),
        ("a graphify/ dir with no graph.json -> still ABSENT, PASS (no-op)", 0, None,
         ALL_FALSE, {"graphify/README.md": "x"}, "graphify"),
    ]


def _run_capturing(fn, *a, **kw):
    """Run a check, returning (rc, everything_it_printed). The title assertion needs the text."""
    import io
    real, buf = sys.stdout, io.StringIO()
    sys.stdout = buf
    try:
        rc = fn(*a, **kw)
    finally:
        sys.stdout = real
    return rc, buf.getvalue()


def selftest():
    """Every case states what it PROVES, and a failing case must fail for the STATED reason.

    THE FIXTURE BASE IS ITSELF A GIT REPO, and that is load-bearing rather than incidental. Every
    tree was previously built in a bare mkdtemp with no outer `.git`, so git's upward discovery had
    nowhere to escape to -- and the one evasion that matters in production (a forged `.git` NESTED
    INSIDE a real checkout, which makes git answer about the ancestor and return success) could not
    fire in the selftest at all. The controls were passing because the environment was unrealistic.
    (s42 defect-hunter, round 6.)
    """
    passed = failed = 0

    def record(ok, name, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            sys.stderr.write("  PASS  %s\n" % name)
        else:
            failed += 1
            sys.stderr.write("  FAIL  %s%s\n" % (name, detail))

    for name, expect, title, caps_text, files, check in _cases():
        base = tempfile.mkdtemp(prefix="repo-guard-selftest-")
        try:
            # make the BASE a real repo -- see the docstring: without this, upward discovery has
            # nothing to escape into and the nested-forgery case cannot fire.
            subprocess.run(["git", "init", "-q", base], capture_output=True, timeout=20)
            _mktree(base, caps_text, files)
            caps, err = read_caps(base)
            if err:
                rc, text = 1, err
            else:
                rc, text = _run_capturing(CHECKS[check], base, caps)
        finally:
            shutil.rmtree(base, ignore_errors=True)
        got = 0 if rc == 0 else 1
        if got != expect:
            record(False, name, " (expected rc %d, got %d)" % (expect, rc))
        elif title and title not in text:
            # Failed, but not for the reason claimed -- the sabotage case that slipped through before.
            record(False, name, " (failed for the WRONG reason: expected %r in output)" % title)
        else:
            record(True, name)

    for name, payload, expect, title in (
        ("automerge: clean PR -> PASS", {"pull_request": {"labels": []}}, 0, None),
        ("automerge: auto_merge ENABLED -> FAIL",
         {"pull_request": {"auto_merge": {"merge_method": "squash"}, "labels": []}}, 1,
         "auto-merge is not permitted"),
        ("automerge: automerge LABEL, case-insensitive -> FAIL",
         {"pull_request": {"labels": [{"name": "AutoMerge"}]}}, 1, "auto-merge is not permitted"),
        ("automerge: unrelated label -> PASS",
         {"pull_request": {"labels": [{"name": "bug"}]}}, 0, None),
    ):
        fd, ep = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            rc, text = _run_capturing(check_automerge, ".", {}, event_path=ep)
        finally:
            os.unlink(ep)
        got = 0 if rc == 0 else 1
        if got != expect:
            record(False, name, " (expected rc %d, got %d)" % (expect, rc))
        elif title and title not in text:
            record(False, name, " (failed for the WRONG reason)")
        else:
            record(True, name)

    # guard-integrity's DECISION, which was 45 lines of untested inline shell until round 3.
    for name, absent, changed, want_rc, want_txt in (
        ('integrity: nothing absent, nothing changed -> PASS', [], [], 0, 'PASS'),
        ('integrity: first adoption (absent on base) -> PASS with a notice',
         ['a.yml'], [], 0, 'first adoption'),
        ('integrity: a STRICT file CHANGED -> FAIL', [], ['a.yml'], 1, 'was modified'),
        ('integrity: changed WINS over absent -- a change is never excused by a first adoption',
         ['a.yml'], ['b.yml'], 1, 'was modified'),
    ):
        rc, lines = integrity_verdict(absent, changed)
        blob = ' '.join(lines)
        if rc != want_rc or want_txt not in blob:
            record(False, name, ' (rc %d, said %r)' % (rc, blob[:80]))
        else:
            record(True, name)
    sys.stderr.write("\n=== SELFTEST: %d passed, %d failed ===\n" % (passed, failed))
    return 0 if failed == 0 else 3


def main():
    ap = argparse.ArgumentParser(description="Portable repo guard engine.")
    ap.add_argument("check", nargs="?", choices=sorted(CHECKS) + ["integrity"])
    # THESE TWO FLAG NAMES ARE A STABILITY CONTRACT, not an implementation detail.
    #
    # guard-integrity invokes `integrity` from the BASE BRANCH's frozen copy of this file while the
    # SHELL passing the flags is always the new one. So a rename here breaks against every base copy
    # still in the field -- in 12 repos, until each one's next sync merges. Add flags, never rename
    # or remove them, and treat the pair below as append-only.
    # (s42 future-proofing-auditor, round 5: an undocumented cross-version contract is a trap.)
    ap.add_argument("--absent", default="", help="integrity: space-separated paths absent on base")
    ap.add_argument("--changed", default="", help="integrity: space-separated paths that differ")
    ap.add_argument("--root", default=".")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.check:
        ap.error("a check is required (or --selftest)")
    if a.check == "integrity":
        rc, lines = integrity_verdict(a.absent.split(), a.changed.split())
        for line in lines:
            out(line)
        return rc
    caps, err = read_caps(a.root)
    if err:
        out("::error title=capability manifest::%s" % err)
        return 1
    return CHECKS[a.check](a.root, caps)


if __name__ == "__main__":
    sys.exit(main())
