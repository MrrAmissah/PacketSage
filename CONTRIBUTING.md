# Contributing to PacketSage

PacketSage is a proprietary, source-available project. It is not open source.
Please read the license before opening an issue, discussion, or pull request.

## Contribution Boundary

By submitting a pull request, patch, issue comment, design suggestion,
documentation change, screenshot, test case, workflow, or other contribution,
you agree that:

* You have the right to submit the contribution.
* The contribution is your original work, or you have permission to submit it.
* The contribution does not include confidential, proprietary, customer,
classified, sensitive, or unlawfully obtained material.
* You grant MrrAmissah and the PacketSage project a perpetual, worldwide,
  irrevocable, royalty-free, sublicensable license to use, reproduce, modify,
  publish, distribute, display, perform, and commercialize your contribution as
  part of PacketSage and related products or services.
* Your contribution may be included in proprietary or commercial versions of
  PacketSage without additional compensation.
* Submitting a contribution does not grant you any ownership interest in
  PacketSage and does not grant you permission to reuse PacketSage outside the
  repository license.

If you cannot agree to these terms, do not submit a contribution.

## What Is Welcome

Useful contributions include:

* Bug reports with clear reproduction steps.
* Security or privacy hardening suggestions.
* Parser accuracy improvements for defensive packet/log formats.
* Documentation corrections.
* Accessibility or reliability fixes.
* Tests that verify existing behavior.

## What Is Not Accepted

Do not submit:

* Offensive security features, exploit helpers, evasion guidance, malware
  behavior, credential theft workflows, or unauthorized access instructions.
* Real customer packet captures, credentials, tokens, private keys, or secrets.
* Third-party code, designs, screenshots, datasets, or generated assets that
  you do not have the right to contribute.
* Broad rewrites, redesigns, or product pivots without prior maintainer
  approval.

## Pull Request Expectations

Before opening a pull request:

1. Keep the change small and focused.
2. Run:
   ```bash
   npm ci
   npm test
   npm run lint
   npm run build
   npm audit
   npm audit --omit=dev
   ```
3. Do not expose secrets or create `VITE_OPENAI_API_KEY` or `VITE_GEMINI_API_KEY`.
4. Preserve the defensive, evidence-bound product boundary.
5. Include screenshots or smoke-test notes for user-facing UI changes.

## Security Reports

Please do not open public issues for vulnerabilities, exposed secrets, or
private deployment details. Contact the repository owner privately with a short
description, reproduction steps, impact, and any safe proof-of-concept details.

## Licensing Questions

If you want to use PacketSage commercially, build on it, redistribute it, teach
from it, host it for others, or incorporate it into another product, request
written permission from the repository owner first.
