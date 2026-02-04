# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-04

Initial public release.

- Shell hook that blocks destructive commands before execution.
- Detection for pipe-to-shell, homograph, and terminal injection threats.
- Context-aware parsing with subshell recursion limits.
- Configurable allow/block lists, thresholds, and modes.
- Audit logging with local rotation.
- Optional shell context snapshot for alias/function safety.

