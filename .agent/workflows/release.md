---
description: Create and push a new git tag to trigger the release pipeline
---

# Release Workflow

This workflow automates the process of tagging a new release and pushing it to GitHub to trigger the CI/CD pipeline.

1.  **Check Git Status**
    Ensure the working directory is clean before tagging.
    ```bash
    git status
    ```

2.  **Create Tag**
    (User must provide the version number, e.g., v0.1.2)
    ```bash
    git tag <VERSION>
    ```

3.  **Push Tag**
    Push the tag to the remote repository to ensure the GitHub Action runs.
    ```bash
    git push origin <VERSION>
    ```
