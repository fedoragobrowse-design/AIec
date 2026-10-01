# Design

AIec is an implementation of the ideas in **DeepSeek Elastic Compute (DSec):
A Sandbox Infrastructure for Effective Agentic Training at Scale** (arXiv:2609.22978),
reduced to what a small, honest implementation can actually stand behind.

This document records which mechanisms came from the paper, which are
independent engineering, and where AIec deliberately does something different.

## The problem the paper names

Agentic training and evaluation need sandboxes that:

- arrive in large bursts rather than steadily,
- span heterogeneous functionality and isolation requirements,
- retain state across long interactions,
- and are drawn from a large image corpus with limited reuse.

DSec's conclusion is that this needs an *elastic execution platform*, not a single
sandbox runtime. Two consequences shape AIec:

1. **One contract, many backends.** A caller should not have to care whether a
   sandbox is a microVM, a container, or a hosted provider's machine.
2. **Ownership must be fenced.** With sandboxes moving between workers, a worker
   that has lost its lease must be unable to touch a sandbox it no longer owns.

## Mechanism mapping

| DSec mechanism | AIec implementation |
|---|---|
| Unified SDK across FnCall / container / microVM / full-VM backends | `SandboxRuntime` in `crates/aiec-core/src/runtime.rs`, implemented by Firecracker, the hosted E2B adapter, and Docker |
| Heterogeneous, capability-aware placement | `RuntimeCapabilities` advertised per worker, persisted, and matched by the scheduler before placement |
| Bursty arrival and resource admission | Per-tenant quotas enforced inside the placement transaction, per-tenant rate limiting, and a global execution budget |
| Sandbox lifecycle with recoverable state | Leased ownership with a monotonic fencing generation; workspace archives in shared object storage, restored on a new owner |
| Image corpora with limited reuse | Content-addressed image references, signed manifests, digest verification before a guest boots |

## Where AIec differs

These are choices, not omissions of the paper.

- **The hosted backend is E2B, not a self-operated fleet.** The paper describes
  operating microVM capacity. AIec has no owned hardware fleet, so hosted
  execution is delegated to a Firecracker-backed provider behind the runtime
  interface. AIec's own Firecracker runtime is complete and is what
  self-hosted deployments run; the hosted fleet is not AIec-operated hardware, and
  the two claims are reported separately rather than merged.
- **Only workspace state is portable.** A snapshot preserves `/workspace`. Running
  VM memory does not survive a worker failure, and AIec does not claim it does.
- **One cluster, self-hosted.** The paper describes a large multi-region fleet.
  AIec is a single self-hosted cluster that one team runs; there is no hosted
  service and no multi-region story.
- **No multi-host validation yet.** Recovery and fencing are proven with two
  workers on one host. Genuinely distributed operation is not yet demonstrated.


## Guard: what the paper does not name

The paper's isolation story ends at the guest boundary. That is the right scope
for training a model, where the model is the thing you are producing. For
deploying an agent that acts on a developer's machine, the interesting failure
is one step further in: a sandbox whose *guest* has been persuaded to want
something the operator never agreed to.

Guard answers that by moving the decisions out of the machine. A sandbox is
still a microVM with its own kernel; what changes is that the answer to "what
may this reach, with whose credentials, and recorded where" is computed on the
worker, from a policy the guest cannot read, using secrets the guest never
holds, into a journal the guest cannot rewrite. The consequence worth stating
is the failure mode: compromising the guest does not grant new capability,
because capability was never expressed in terms the guest could influence.

Three design choices follow from that, and each one is a refusal rather than a
capability:

- **A policy is verified before it is applied.** A finite rule model is checked
  against the operator boundary at compile time, and a rule naming a blocked
  destination is a configuration error, not a runtime surprise.
- **Evidence is written before an action, not after.** A cut that cannot be
  recorded is not taken, and a journal that cannot be written cuts the gateway
  permanently rather than continuing unobserved.
- **What cannot be enforced is refused.** Encrypted tunnels are not inspected,
  so a rule needing method or tool visibility is rejected on that path instead
  of being recorded as satisfied. The same reasoning is why an OpenShell policy
  carrying binary-scoped rules is refused rather than translated: an
  out-of-guest gateway cannot verify which executable opened a connection, and
  pretending otherwise would be a weaker policy wearing a familiar name.

The full contract, the operator settings and the phase-by-phase status are in
[`GUARD_POLICY.md`](../GUARD_POLICY.md),
[`docs/guard-plan.md`](guard-plan.md) and
[`docs/openshell-compatibility.md`](openshell-compatibility.md).

## Fencing, in detail

A sandbox is owned through a lease carrying a generation that only ever
increases. Every state-changing operation is checked against the current owner
and generation before the runtime is touched:

```
worker A owns generation N
  → A dies
  → its lease expires
  → the control plane reassigns to worker B at generation N+1
  → B reconstructs the workspace from the newest archive
  → if A returns, its generation-N operations are rejected
```

This is why the lease lives in the database rather than in a worker's memory: a
restarted worker that still believes it owns a sandbox must be told otherwise.


## What AIec does not do

- No GPU, QEMU or browser runtime.
- No multi-region scheduler, enterprise SSO, or organisation hierarchy.
- No marketplace, and no admin dashboard — the product is API and SDK driven.
- No complete data-loss prevention. Model prompts remain an information channel,
  and Guard governs egress, credentials and evidence rather than inspecting what
  an agent says.
- No production claim for Guard yet. The live Firecracker acceptance run is not
  executed; [`docs/guard-plan.md`](guard-plan.md) records exactly what has and
  has not been observed.

## Reference

> Jialiang Huang, Hongxuan Tang, Jingchang Chen, Yuxuan Liu, Yixiao Chen, Yuan
> Cheng, Yi Tao, Jingli Zhou, Yupeng Chen, Haoyu Chen, Jiarui Wang, Shengkai Lin,
> Chuqi Zhang, Bryan Lee Teng, Lian Guo, Zhe Fu, Wenjun Gao, Yisong Wang, Liang
> Zhao, Zehao Wang, Ziwei Xie, Yongqiang Guo, Peixin Cong, Ziyi Gao, Shuiping Yu,
> Hanwei Xu, Zuofan Wu, Zhizhou Ren, Yuyang Zhou, … Mingxing Zhang, Liyue Zhang,
> Panpan Huang, Wenfeng Liang.
> **DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for Effective
> Agentic Training at Scale.** DeepSeek-AI & Tsinghua University, 2026.
> arXiv:2609.22978.
