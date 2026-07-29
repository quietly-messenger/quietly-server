# Contributing to Quietly

Thanks for your interest in Quietly. This project is early-stage and currently maintained by a solo developer (with AI-assisted development), so this guide will evolve as the project grows. Right now it explains where things stand and how to get involved in a way that's actually useful.

## Where we are right now

Quietly is in active early development. The architecture, protocol, and codebase are still moving fast, which means:

- **Feedback, bug reports, and testing are the most valuable contributions today.**
- **Code contributions are welcome**, but since the project is young and the core maintainer is still shaping the architecture, it's best to open an issue or discussion *before* starting significant work — this avoids wasted effort on something that might get redesigned. Small fixes (typos, obvious bugs, docs) don't need this step.
- Expect breaking changes. Nothing here is stable yet.

## Repository structure

Quietly is split across multiple repositories rather than a single monorepo:

- **`quietly-client`** — the Flutter app (Android first)
- **`quietly-server`** — the Go home server and federation gateway
- **`quietly-crypto`** — the cryptographic core (X3DH, Double Ratchet, and related primitives)

Each repository may have its own `CONTRIBUTING.md` with repo-specific details (build steps, dependencies). This file covers the things that apply across all of them.

## Reporting bugs and giving feedback

- General bugs, UX feedback, and feature suggestions → open a GitHub issue in the relevant repo.
- Please include steps to reproduce, what you expected, and what actually happened. For app issues, your device/OS version helps a lot.
- Before filing, a quick search of existing issues avoids duplicates.

## Reporting security vulnerabilities

**Do not open a public issue for security vulnerabilities.** Given that Quietly handles end-to-end encrypted communication, a publicly disclosed flaw in the protocol or its implementation could put real users at risk before a fix ships.

Instead, please use **GitHub Security Advisories** on the relevant repository (look for the "Report a vulnerability" option under the Security tab). This creates a private disclosure channel between you and the maintainer until a fix is ready.

We ask for reasonable time to investigate and patch before any public disclosure. Responsible disclosure will always be credited, if you'd like it to be.

## Proposing code changes

1. Open an issue or discussion first for anything non-trivial, so we can align on direction.
2. Fork the relevant repository and work in a feature branch.
3. Keep commits focused and write clear commit messages — we loosely follow [Conventional Commits](https://www.conventionalcommits.org/) (`fix:`, `feat:`, `docs:`, etc.) but won't reject a PR over formatting alone.
4. Match the existing code style for that repo:
   - Go: `gofmt` / `go vet` clean
   - Flutter/Dart: `dart format`
   - Zig: `zig fmt`
5. Open a pull request describing *what* changed and *why*. Link the related issue if there is one.

Given the subject matter, contributions touching cryptographic code, key handling, or the federation trust model will get extra scrutiny and may take longer to review — that's not a reflection on the quality of the work, just the nature of a security-sensitive project.

## Licensing

Quietly is licensed under **AGPL-3.0**. By submitting a contribution, you agree it will be distributed under the same license. This matters especially for the server and protocol code: AGPL ensures that anyone who runs a modified version of Quietly as a network service must also share their changes — the same freedom you're extending to others is protected for you too.

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). Be respectful, assume good faith, and keep disagreements about code, not people. A `CODE_OF_CONDUCT.md` file with the full text will be added alongside this guide.

## What's most helpful right now

If you're looking for where to start:

- **Testing on real Android devices** and reporting rough edges.
- **Reviewing the cryptographic design** (see the architecture notes) — outside eyes on the protocol before it's locked in are extremely valuable.
- **UX feedback** — does it feel as simple as it should?

Thanks for taking the time to read this — and for caring about a messenger that doesn't ask you to trade privacy for a good experience.
