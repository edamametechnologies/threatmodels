#!/usr/bin/env bash

set -euo pipefail

WORKFLOW_FILE=".github/workflows/test_models.yml"
WORKFLOW_NAME="$(basename "${WORKFLOW_FILE}")"

err() {
  echo "[$(basename "$0")] $*" >&2
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Missing required command '$1'. Please install it first."
    exit 1
  fi
}

require_cmd git
require_cmd gh

if ! gh auth status >/dev/null 2>&1; then
  err "GitHub CLI is not authenticated. Run 'gh auth login' first."
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [[ ! -f "$WORKFLOW_FILE" ]]; then
  err "Unable to find workflow file $WORKFLOW_FILE. Are you in the threatmodels repo?"
  exit 1
fi

BASE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BASE_BRANCH" == "HEAD" ]]; then
  err "Detached HEAD state is not supported. Please switch to a branch."
  exit 1
fi

TMP_BRANCH="ci/test-models-$(date +%s)"
STASH_REF=""

cleanup() {
  set +e
  git checkout "$BASE_BRANCH" >/dev/null 2>&1
  git push origin --delete "$TMP_BRANCH" >/dev/null 2>&1
  git branch -D "$TMP_BRANCH" >/dev/null 2>&1
  if [[ -n "$STASH_REF" ]]; then
    git stash apply "$STASH_REF" >/dev/null 2>&1
    git stash drop "$STASH_REF" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

if git show-ref --verify --quiet "refs/heads/$TMP_BRANCH"; then
  git branch -D "$TMP_BRANCH" >/dev/null 2>&1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  STASH_NAME="run-tests-$(date +%s)"
  git stash push --include-untracked -m "$STASH_NAME" >/dev/null
  STASH_REF="$(git stash list | grep "$STASH_NAME" | head -n1 | cut -d: -f1)"
fi

git checkout -b "$TMP_BRANCH" "$BASE_BRANCH" >/dev/null 2>&1

if [[ -n "$STASH_REF" ]]; then
  git stash apply "$STASH_REF" >/dev/null
  git add -A
  git commit -m "[run-tests] temporary snapshot for CI" >/dev/null
fi

PUSH_SHA="$(git rev-parse HEAD)"
git push -u origin "$TMP_BRANCH" >/dev/null 2>&1

git checkout "$BASE_BRANCH" >/dev/null 2>&1
if [[ -n "$STASH_REF" ]]; then
  git stash apply "$STASH_REF" >/dev/null
  git stash drop "$STASH_REF" >/dev/null
  STASH_REF=""
fi

echo "Triggering workflow '$WORKFLOW_NAME' on branch '$TMP_BRANCH'..."
gh workflow run "$WORKFLOW_NAME" --ref "$TMP_BRANCH"

echo "Waiting for the workflow run associated with commit $PUSH_SHA to appear..."
RUN_ID=""
for _ in {1..30}; do
  RUN_ID="$(gh run list \
    --workflow "$WORKFLOW_NAME" \
    --branch "$TMP_BRANCH" \
    --limit 20 \
    --json databaseId,headSha,status,createdAt \
    --jq "map(select(.headSha == \"$PUSH_SHA\"))[0].databaseId")"
  if [[ -n "${RUN_ID}" && "${RUN_ID}" != "null" ]]; then
    break
  fi
  sleep 3
done

if [[ -z "${RUN_ID}" || "${RUN_ID}" == "null" ]]; then
  err "Could not determine the workflow run ID. Verify the workflow was created on GitHub."
  exit 1
fi

echo "Watching workflow run ${RUN_ID}..."
gh run watch "${RUN_ID}" --exit-status

echo "Workflow completed. Cleaning up temporary branch..."

echo "Collecting logs for run ${RUN_ID}..."
JOB_JSON="$(mktemp)"
if gh run view "${RUN_ID}" --json jobs > "${JOB_JSON}"; then
  FAILING_JOBS=$(jq -r '.jobs[] | select(.conclusion != "success") | "\(.databaseId)\t\(.name // "unknown")"' "${JOB_JSON}")
  if [[ -z "${FAILING_JOBS}" ]]; then
    echo "All jobs succeeded; no error logs to display."
  else
    echo "---- Extracted error lines ----"
    while IFS=$'\t' read -r JOB_ID JOB_NAME; do
      [[ -z "${JOB_ID}" ]] && continue
      echo "[Job ${JOB_ID}] ${JOB_NAME}"
      JOB_LOG="$(mktemp)"
      if gh run view "${RUN_ID}" --job "${JOB_ID}" --log > "${JOB_LOG}"; then
        if ! grep -E '(\[ERROR\]|^Error:)' "${JOB_LOG}"; then
          echo "(no error lines found)"
        fi
      else
        echo "(failed to download logs)"
      fi
      rm -f "${JOB_LOG}"
      echo "--------------------------------"
    done <<< "${FAILING_JOBS}"
  fi
else
  err "Failed to retrieve job metadata for run ${RUN_ID}"
fi

rm -f "${JOB_JSON}"
