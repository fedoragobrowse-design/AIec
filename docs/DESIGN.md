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
