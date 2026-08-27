---
name: False positive
about: A measurement fired when it should not have
title: "false positive: <metric or claim id> on <what the code was>"
labels: false-positive
---

<!--
This template is for a finding that is WRONG: a detector or metric fired on a
change that did not do what the finding says.

The opposite case — Andon should have fired and did not, or a change got past
the tool — is not an issue. It is a security report: see SECURITY.md and use
the private route. Do not describe an evasion here.
-->

## The finding

The `metric_id` or `claim_id` from the finding (`andon explain --list` prints
every one):

```
tamper.example
```

The finding as Andon printed it — from `andon report`, or the entry from
`andon measure --json`:

```
```

## What the code actually was

The smallest before-and-after that reproduces the finding. Real code is better
than a description; a `base/` and `head/` pair in the shape of
`fixtures/honest/corpus/<detector>/<case>/` is best, because a confirmed false
positive becomes a should-not-fire case there.

```
```

## Why the finding is wrong

What the change did, and why the finding's reading of it does not hold. If
`andon explain <id>` lists what the metric does not predict and the finding is
being read as predicting exactly that, say so — that is a documentation gap
rather than a detector gap, and it is fixed differently.

## `andon doctor`

Run `andon doctor` in the repository the measurement ran in. It writes
`andon-doctor.json` to the current directory; attach that file. It is the
self-report bundle a maintainer needs to tell a reproducible finding from a
machine-specific one. Read it before attaching and remove anything you
consider private.

## Checklist

- [ ] I ran `andon explain <id>` and read the claim and its `does_not_predict`.
- [ ] This is a finding that fired wrongly, not a missed detection (see `SECURITY.md`).
- [ ] `andon-doctor.json` is attached, or I have said why not.
