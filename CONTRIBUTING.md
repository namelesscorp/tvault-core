# Contributing (tvault-core)

## Workflow

### 1. Create branch

When starting work on a new feature, bug fix, or task, create a new branch following this naming convention:
```
[feature | bug_fix | task]/[PROJECT_GROUP]-[TASK-NUMBER]
```
example:
```
feature/BACKEND-1
```
This helps us quickly identify the group or team responsible for the task.

### 2. Update the Changelog

Make sure to update the `CHANGELOG.md` file with details about the changes you’ve made. 
Follow the format used in the changelog and provide clear, concise entries for any new features, bug fixes, or breaking changes.

### 3. Open Merge Request and Gather Approvals

Once your changes are complete, open a **Merge Request (MR)**:
- Write title and description
```
Title: [PROJECT_GROUP]-[TASK-NUMBER] Some title
Description: [PROJECT_GROUP]-[TASK-NUMBER] Some description
```

Example:
```
Title: BACKEND-1 Init repository
Description: BACKEND-1 Init repository and update README
```

Ensure that you request approvals from the appropriate team members. 
Typically, the following people should approve:
- At least one team member from your team.
- A reviewer from the relevant department (Frontend/Backend, e.g).
- A technical lead or senior developer for major changes.

**Note**: No merge should be performed without the required approvals.

### 4. Test Your Code

Before creating a merge request, **test your changes thoroughly**. 
Ensure that your code does not introduce regressions, and all new functionality works as expected. 

Follow these steps:
- Run the application locally.
- Execute any existing unit or integration tests.
- Add new tests if necessary to cover new functionality.

### 5. Merge Changes

Once the merge request is approved and all tests pass, you can merge your changes into the main/master (or appropriate) branch. 
Be sure to follow these steps:
- Ensure there are no merge conflicts.
- Use Squash and Merge to keep the commit history clean.
- Add a clear description of what the merge includes.

### 6. Create a Tag

After merging the code, create a new version tag following the versioning convention used by the project (e.g., v1.2.0).

To create a tag, use the following git command:
```shell
# Create a tag
git tag -a v1.2.0 -m "Release version 1.2.0"

# Push the tag to the remote repository
git push origin v1.2.0
```

This helps track version history and is essential for deployments and release management.

## General Guidelines

Commit Message Format:
- Keep commit messages clear, concise, and descriptive.
- Start with an imperative verb (e.g., “Add”, “Fix”, “Refactor”).
- Follow this format for the subject line: ```[PROJECT_GROUP]-[TASK-NUMBER] Short description of the change```

Example:
```
BACKEND-1 Init repository
```

Code Style:
- Follow the coding style guidelines defined for the project. Adhere to the rules for indentation, naming conventions, and code structure.
Documentation:
- Update the relevant documentation if your changes affect user-facing features, API endpoints, or configuration.
Merge Request Description:
- Provide a detailed description of the changes you made in the PR.
- Reference any issues or tickets (e.g., Closes BACKEND-1).