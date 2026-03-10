# Project Governance

This document describes how the Wild project is governed.

## Roles

### Maintainers

* [davidlattimore](https://github.com/davidlattimore) (lead maintainer)  
* [lapla-cogito](https://github.com/lapla-cogito)
* [marxin](https://github.com/marxin)
* [mati865](https://github.com/mati865)

### Contributors

People who contribute to Wild can be added to the GitHub org. This can be done when an individual
requests to be added. They should have already made a few contributions. We may periodically remove
people who haven't contributed in more than a year.

## Maintainer roles

* Reviewing PRs  
* Triaging issues  
* Assigning issues  
* Releasing

## Decision making process

Major decisions should be decided as PRs in the [RFCs repo](https://github.com/wild-linker/rfcs).
They are decided by majority vote with ties broken by the lead maintainer. However, reaching a
common consensus should always be attempted first. Votes are counted after 7 days. Voting can
optionally be closed early if a unanimous vote is reached.

## Code reviews

All submitted code must be via GitHub pull requests. PRs should be reviewed and approved by at least
one maintainer other than the author with the following exceptions:

* Maintainers can submit changes without review if they’re trivial in nature or time sensitive. e.g.
  CI is broken and needs to be fixed, typo fixes and other similar minor changes provided they are
  judged to be uncontroversial.  
* The lead maintainer can submit changes without review. This is mostly because there isn’t yet
  sufficient review capacity to do otherwise. Once sufficient review capacity exists, this exception
  should be removed.

## Communication

### Meetings

Meetings are held monthly and are open to anyone. To join the meetings, please join the
[wild-dev-meetings](https://groups.google.com/g/wild-dev-meetings) google group. Timing of the
meeting is subject to change if the lead maintainer isn’t available. Meetings can be used to try to
reach consensus on issues, however the actual decision / voting still happens via the relevant PRs.

### Zulip

The Wild project has a [Zulip instance](http://wild.zulipchat.com/) where discussions can also take
place.

## Releasing

Releases should ideally be done every 1 to 2 months following the procedure in
[RELEASING.md](RELEASING.md). This schedule is flexible and releases may be more or less frequent
depending on circumstances.

## Addition and removal of maintainers

Requirements to become a maintainer:

* 6 or more months of quality contributions to the project.  
* Positive interactions with the community.  
* Able to commit at least 5 hours per month  
* Nominated by an existing maintainer.  
* Unanimous agreement among all maintainers

Maintainers can resign at any time.

Maintainers can be removed by unanimous decision of the other maintainers provided there is good
cause. e.g. if the maintainer has been inactive for a substantial period of time and isn’t
responding.

## Periodic review

This governance policy should be reviewed at least once per year and updated if necessary.
Substantive changes to the policy have the same requirements for approval as major changes, except
that they take place in the main repository.

## Succession

In the event that the lead maintainer is no longer available to contribute, the remaining
maintainers can either appoint a new lead by unanimous vote, or change the project governance to not
have a specific lead.

## Wind down process

In the event that the Wild project ends, any assets held by the project are to be transferred to the
Rust Foundation.

## Code of Conduct

The Wild project adheres to the [Rust code of
conduct](https://rust-lang.org/policies/code-of-conduct/). If you have any moderation concerns or
queries, please email [wild-mod@googlegroups.com](mailto:wild-mod@googlegroups.com).
