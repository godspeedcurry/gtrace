---
name: Wails Release Management
description: Standard procedure for releasing the GTrace Wails application, including pre-release checks and tag management.
---

# Wails Release Management

This skill provides a checklist and commands for releasing the GTrace Wails application.

## 1. Pre-Release Checks
GoReleaser requires a clean git state.

1.  **Check Status**:
    ```bash
    git status
    ```
    Ensure "nothing to commit, working tree clean".

2.  **Verify Gitignores**:
    Ensure build artifacts are ignored so they don't dirty the state during build:
    - `frontend/node_modules/`
    - `frontend/dist/`
    - `build/bin/`

## 2. Triggering a Release
Releases are triggered automatically by pushing a semantic version tag (e.g., `v1.0.0`).

1.  **Create Tag**:
    ```bash
    git tag v0.1.x
    ```

2.  **Push Tag**:
    ```bash
    git push origin v0.1.x
    ```

## 3. Troubleshooting
- **Dirty State Error**: If GoReleaser fails with "git is in a dirty state", likely `npm install` modified `package-lock.json` or build scripts generated untracked files.
    - **Fix**: Use `npm ci` in CI workflows.
    - **Fix**: Add generated folders to `.gitignore`.
