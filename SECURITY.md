# libwebem Security Policy

libwebem is the embedded HTTP/HTTPS server library used by [Domoticz](https://github.com/domoticz/domoticz) and is maintained as part of the Domoticz Open Source project. This document describes how to report a security issue in the library itself.

  * [Reporting a Vulnerability](#reporting-a-vulnerability)
  * [Disclosure Policy](#disclosure-policy)
  * [Scope](#scope)

## Reporting a Vulnerability

We take all security vulnerabilities seriously. Thank you for improving the security of our open source software. We appreciate your efforts and responsible disclosure, and will make every effort to acknowledge your contribution.

**The preferred channel is GitHub private vulnerability reporting**, which keeps the report private to the maintainers until an advisory is published, and lets us coordinate the fix and credit you in the same place:

  * [Report a vulnerability in domoticz/libwebem](https://github.com/domoticz/libwebem/security/advisories/new)

If you would rather not use GitHub, or you do not have an account, email us at:

    security@domoticz.com

Normally we will acknowledge your report within 24 hours, and will send a more detailed response within a week indicating the next steps in handling it. After the initial reply, we will endeavor to keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

### What helps us

Reports are easiest to act on when they include the affected version or commit, the steps or request needed to reproduce the issue, and what an attacker gains. If you can say what you did *not* observe, or what turned out not to be exploitable, that is genuinely useful and saves us both time. Proof-of-concept code is welcome but not required.

Please give us a reasonable opportunity to ship a fix before disclosing publicly. We will not take legal action against researchers who report in good faith and act accordingly.

## Disclosure Policy

When we receive a security bug report, it is assigned to a primary handler who coordinates the fix and release process:

  * Confirm the problem and determine which versions are affected.
  * Audit the code for similar problems elsewhere in the library.
  * Prepare and test a fix, with a regression test where practical.
  * Publish a [GitHub Security Advisory](https://github.com/domoticz/libwebem/security/advisories) once fixed builds are available, crediting the reporter unless they ask otherwise.

We are happy to request a CVE as part of an advisory if you would like one. If you have already engaged a third-party CNA, tell us and we will coordinate rather than publish a competing record.

Because libwebem has no release tags of its own, fixes are delivered by advancing the submodule pointer in the consuming application. Advisories therefore identify the fix by libwebem commit and, where relevant, by the Domoticz release that first carries it.

## Scope

libwebem is a library, not a standalone service. It has no default deployment of its own, and its security properties depend in part on how the embedding application configures it — in particular authentication, TLS termination, trusted proxy settings, and which handlers are registered.

In scope: defects in the library itself, such as HTTP request parsing and framing, header handling, session and cookie management, TLS setup, access control primitives, and resource-exhaustion limits.

Out of scope: issues that exist only in an embedding application's own handlers. If the issue is in Domoticz rather than in libwebem, please report it against [domoticz/domoticz](https://github.com/domoticz/domoticz/security/advisories/new) instead. If you are not sure which side a problem falls on, report it anyway and say so — working that out is our job, not yours.
