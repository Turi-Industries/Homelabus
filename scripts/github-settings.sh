#!/usr/bin/env bash
#
# The repository's settings on GitHub, applied through its API: what a click in the
# web interface would set, written down so it can be read, reviewed and applied again.
# Every call sets a value rather than toggling one, so running it twice changes nothing.
#
#   scripts/github-settings.sh [owner/repo]     # needs `gh auth login` as an admin
#
# ⚠️ On a free organisation, rulesets, secret scanning, push protection and private
# vulnerability reporting exist for PUBLIC repositories only. While the repository is
# private those steps are skipped and said so: run this again the day it opens.
set -euo pipefail

repo=${1:-Turi-Industries/Homelabus}
api() { gh api --silent -H "Accept: application/vnd.github+json" "$@"; }
step() { printf '• %s\n' "$*"; }

visibility=$(gh api "repos/$repo" --jq .visibility)
step "$repo is $visibility"

step "description, features, merging"
api -X PATCH "repos/$repo" --input - <<'JSON'
{
  "description": "Self-hosting platform for a Docker Swarm cluster: apps installed from what they need, shared databases, SSO, backups and updates. An absence never looks like a success.",
  "has_wiki": false,
  "has_projects": false,
  "has_issues": true,
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "allow_update_branch": true,
  "delete_branch_on_merge": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY"
}
JSON
gh repo edit "$repo" --enable-discussions >/dev/null

step "topics"
api -X PUT "repos/$repo/topics" --input - <<'JSON'
{ "names": ["homelab", "self-hosted", "docker-swarm", "rust", "sveltekit", "backup", "oidc", "infrastructure"] }
JSON

# A workflow's token reads unless a job asks for more (`workflows.rs` holds every job to
# that), and only the actions this repository names may run, each by its commit.
step "Actions: read-only token, named actions only, pinned by commit"
api -X PUT "repos/$repo/actions/permissions" --input - <<'JSON'
{ "enabled": true, "allowed_actions": "selected", "sha_pinning_required": true }
JSON
api -X PUT "repos/$repo/actions/permissions/selected-actions" --input - <<'JSON'
{
  "github_owned_allowed": true,
  "verified_allowed": false,
  "patterns_allowed": [
    "docker/*",
    "dtolnay/rust-toolchain@*",
    "Swatinem/rust-cache@*",
    "oven-sh/setup-bun@*",
    "sigstore/cosign-installer@*",
    "ossf/scorecard-action@*",
    "fsfe/reuse-action@*"
  ]
}
JSON
api -X PUT "repos/$repo/actions/permissions/workflow" --input - <<'JSON'
{ "default_workflow_permissions": "read", "can_approve_pull_request_reviews": false }
JSON

# Alerts only: Renovate opens the pull requests, and Dependabot's would be the same
# ones twice.
step "Dependabot alerts"
api -X PUT "repos/$repo/vulnerability-alerts"
api -X DELETE "repos/$repo/automated-security-fixes"

if [[ $visibility != public ]]; then
    step "skipped while $visibility: secret scanning, private vulnerability reporting, the rules on main"
    exit 0
fi

# Read back, not trusted: right after the repository turns public, GitHub answers 200
# and leaves both disabled (seen 2026-10-27). A setting said done must be done.
step "secret scanning and push protection"
for attempt in 1 2 3 4 5; do
    api -X PATCH "repos/$repo" --input - <<'JSON'
{ "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" } } }
JSON
    state=$(gh api "repos/$repo" --jq '.security_and_analysis | .secret_scanning.status + " " + .secret_scanning_push_protection.status')
    [[ $state == "enabled enabled" ]] && break
    if [[ $attempt == 5 ]]; then
        echo "✗ secret scanning still says: $state" >&2
        exit 1
    fi
    sleep 10
done

step "private vulnerability reporting (SECURITY.md points to it)"
api -X PUT "repos/$repo/private-vulnerability-reporting"

# `main` is never rewritten nor deleted, and moves by a pull request the gate passed. The
# maintainer, alone, may bypass it: a project with one person cannot require a second
# reviewer, and a ruleset nobody can satisfy gets switched off.
step "the rules on main"
ruleset=$(cat <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"] } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "Format and lint" },
          { "context": "Tests" },
          { "context": "Interface" },
          { "context": "Interface in a browser" },
          { "context": "Known vulnerabilities" },
          { "context": "Minimum supported Rust version" },
          { "context": "Licensing" } ] } }
  ]
}
JSON
)
id=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name == "main") | .id')
if [[ -n $id ]]; then
    api -X PUT "repos/$repo/rulesets/$id" --input - <<<"$ruleset"
else
    api -X POST "repos/$repo/rulesets" --input - <<<"$ruleset"
fi

# A published release's files and tag can no longer change: a download verified today
# is the one verified tomorrow. ⚠️ A broken release is fixed by a NEW version — its tag
# stays taken even once the release is deleted. `gh release create` attaches the files
# to a draft and publishes last, which immutability requires.
step "immutable releases"
api -X PUT "repos/$repo/immutable-releases"

step "done"
