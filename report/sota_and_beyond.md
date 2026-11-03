# All-or-Nothing Code Blocks: position against the state of the art, and directions beyond it

Report date: 2026-11-03. Inputs: the thesis as it stands on `main` (`master.pdf`, the
*static* iteration), the `dynamic` branch of this repository (the start of the *dynamic*
iteration), and the literature overview *Syscall Restriction and Atomic Code Execution:
Literature Overview*.

> **About the sources.** The overview was compiled from memory, and its authors say so. The
> titles, authors and venues below come from it, from the thesis bibliography, or from my own
> knowledge, and works marked **(verify)** are ones I bring in that the overview does not list.
> Check every reference before citing it. Statements about glibc were checked on this machine
> (Debian glibc 2.41-12+deb13u4).

---

## 0. Short answers

**Static iteration (main).** The primitive is new; the system call defense built on it is not.

- **New.** Your contribution is a *kernel-enforced* guarantee that a block of user-space code on
  a commodity OS either runs from its first instruction to its last or is caught. The kernel
  observes only two gates, and a **signal rule** makes the guarantee sound against handlers and
  forged signal frames. No hardware support, hypervisor or kernel source change is needed.
  The *property* is old: SMART, VRASED and APEX enforce "enter only at the first instruction,
  leave only from the last, no interruption" in hardware on microcontrollers. Moving it into a
  general-purpose kernel through trapping gates, a static condition and a signal rule is, as far
  as I know, not done by any listed work.
- **Already done.** At security level L1, the thesis's own result (§4.1.6: "same guarantee as a
  seccomp filter at the same site") makes the defense equivalent to things that exist:
  **pinsyscalls(2)** on a statically linked OpenBSD binary, **Authenticated System Calls**
  (2005), or a per-instruction-pointer seccomp filter. All of them refuse vector A (`execve` at
  `read`'s `syscall`) and vector B (a misaligned site). All of them leave the attacker every
  required system call with chosen arguments, just as jumping to an AoN ingress gate does.
  Two more claims were made before, by ASC and by OpenBSD static pinning: that the policy comes
  from the build, and that the kernel check does not depend on the policy.
- **Biggest positioning gap.** Chapter 3 of the thesis has no section on atomic or
  controlled-entry execution. It does not cite SMART, VRASED, APEX, Sancus, Fides, SGX,
  TrustLite, Bershad's restartable atomic sequences, Authenticated System Calls, kBouncer,
  ROPecker, Griffin or FlowGuard. These are the works an examiner will hold against the
  primitive. As it stands, the novelty claim rests on comparisons with seccomp and pinsyscalls,
  which are the comparisons the thesis *ties*.

**Dynamic iteration (`dynamic` branch).** It can be innovative, but only if it does more than
port the static scheme to `libc.so`.

- The branch has the undefended baselines so far: `dynamic/cat` (glibc wrappers) and
  `dynamic/cat_bare` (bare wrappers in the program, glibc for the rest).
- "AoN-hardened shared libc, loader registers the region, kernel pins sites" is what OpenBSD
  already deploys with `msyscall`/`pinsyscalls` and `ld.so`. "Per-program system call set for a
  dynamically linked binary" is what sysfilter, Confine, Chestnut and Nibbler already do.
- The real open problems, all of them publishable systems problems, are these:
  1. a **per-process required set enforced over shared library pages**, which pinsyscalls does
     not have (it pins all of libc);
  2. **B3 for code that is mapped after `execve`** (the DSOs and `dlopen`);
  3. **compatibility with glibc as it really is**: it routes cancellable system calls through a
     *generic* site, restarts system calls, and uses the vDSO, threads and signals;
  4. optionally, **transparency down to unmodified glibc binaries**, through load-time rewriting.
- To stand out at the level of the *security guarantee*, the next iteration needs a use of
  execution trust that **no check on the entry state can give**. §6 lists candidates.

---

## 1. What each iteration claims

### 1.1 Static iteration (master.pdf)

| Element | Content |
|---|---|
| Primitive | AoN block = ingress gate (`ud2`, #UD → die notifier arms the thread) + straight-line body + egress gate (`syscall`, kprobe on `x64_sys_call` checks and disarms the thread). One armed bit per thread. |
| Soundness conditions | Static condition B4 (no explicit control transfer in the body); dynamic condition B5 via the **signal rule** (disarm before any handler; `rt_sigreturn` never re-arms). |
| Block identity | AoN region `[__start_aon_text,__stop_aon_text)` from an ELF note read at exec (B3); build-time verifier ensures that the only `0f 0b` pairs in the region are the ingress gates. |
| Application | Hardened named (bijective) wrappers `ud2 ; mov $nr,%eax ; syscall`, one section each, static link with `--gc-sections` → **required system calls** = linked wrappers (D1–D3); every `syscall` outside the region is refused (D4) → L1. |
| Claimed differences vs seccomp | Pins the number instead of checking it; the kernel check is policy-independent; the policy comes from the build. Costs about +400 ns per call vs about +11 ns for a seccomp filter on the number. |
| Stated limits | L1 only, registers not memory, static nolibc only, `int $0x80` unchecked, region not sealed, restarted system calls refused. |

### 1.2 Dynamic iteration (`dynamic` branch, today)

- `dynamic/cat`: ordinary PIE linked against glibc. Vector A reuses an aligned `syscall` inside
  `libc.so.6` and vector B the misaligned site in `benign_compute`. Both win.
- `dynamic/cat_bare`: same program, but open/read/write/close go through the program's own bare
  `mov $nr,%eax ; syscall ; ret` wrappers (`syscalls.S`). Both vectors still win, so moving the
  sites out of libc defends nothing by itself.
- Stated purpose: a **transparent** solution that also works with dynamically linked libraries.
- **Side finding (worth fixing in the scenario).** On glibc 2.41, `read()` contains no
  `syscall`. It calls the generic cancellation path (`__syscall_cancel` → `__syscall_cancel_arch`),
  which takes the number as an argument. `leak_read_syscall()` scans 64 bytes from `&read`, so the
  first `0f 05` it finds is `readlink+5` (`mov $0x59,%eax ; syscall`), the next function. I checked
  this under gdb: the gadget is `readlink + 5 in section .text of libc.so.6`. The attack still
  works, but the comment in `dynamic/cat/cat.c` ("read() is `... ; syscall ; cmp ; jae ; ret`")
  is wrong for this glibc. It is also the first concrete sign of the obstacle in §4.3: in modern
  glibc, `read` has **no bijective site**.

---

## 2. The static iteration against the literature

Legend for *relevance*: ★★★ = must be discussed and cited in Chapter 3, ★★ = should be cited,
★ = background only.

### 2.1 Restricting a process to its intended system calls

| Work | Overlap with the static iteration | What the static iteration does differently | Rel. |
|---|---|---|---|
| **Authenticated System Calls** (Rajagopalan et al., DSN 2005) — *not cited* | A trusted installer analyses the binary and binds each site to its system call number, its address and constant arguments, under a MAC that the kernel checks. This is "the policy comes from the build", the number is bound to the site, the kernel check does not depend on the policy, and misaligned or injected sites are refused. Jumping onto a site with another number fails the MAC or policy check, so **vector A and vector B are both refused**. | ASC *checks* the number and arguments with crypto, while AoN *pins* the number by trusted execution. ASC already covers part of L2 (constant arguments); AoN stays at L1. ASC needs binary rewriting and per-call MAC verification; AoN needs a kernel extension and an extra kernel entry. | ★★★ |
| **pinsyscalls(2) / msyscall(2)** (OpenBSD) — cited | One accepted site per system call number. For **static executables**, the kernel pins the sites the binary itself declares (thesis p. 31). So with a static binary only the linked wrappers are pinned, which is again the required set with the policy from the build. Vector A is refused (59 ≠ the pinned number of `read`'s site) and so is vector B (not pinned). | **No difference in the L1 outcome.** The thesis argues (§1.3, §3.3.4) that pinsyscalls "cannot tell a call of a registered wrapper from a jump to its `syscall`". At L1 that does not change what the attacker gets: with AoN the attacker jumps to the ingress gate and obtains the same system call with the same chosen arguments. The real difference is the mechanism: AoN is generic, pinsyscalls is specific to system calls. | ★★★ |
| **seccomp-BPF with per-IP rules** | §4.1.6 already concedes equality for policies on register values. | The policy source (build vs filter), pin vs refuse, and ASLR, which makes per-IP filters impractical (§3.4). | ★★★ (already in) |
| **BASTION** (Jelesnianski et al., ASPLOS 2023) — cited | Also tries to make "how the system call was reached" part of the policy: the call type, the call-stack path, and argument integrity through shadow copies. | BASTION covers L2-ish argument integrity and context, through a monitor process, ptrace and instrumentation. AoN gives a narrower guarantee that is enforced by the kernel and needs no hardware. BASTION's shadow writes are user-space code, and an AoN block could make such writes **non-skippable** (§6, D-3). | ★★★ |
| **Wagner & Dean** (S&P 2001) | The basis for deriving the allowed set from the code, and for accepting an over-approximation. Their simplest model is a *set* of system calls, which is what L1 is. | AoN derives the set from link-time inclusion and analyses nothing. Their automaton models (call graph, pushdown) are a ready-made route beyond L1 (ordering). Cite them, together with **mimicry attacks** (Wagner & Soto, CCS 2002, **verify**), to bound what L1 leaves: any sequence of required system calls. | ★★ |
| sysfilter, Confine, Chestnut (2020–21) | Automatic per-program allow-lists. sysfilter and Confine are cited. | AoN removes the analysis for static binaries (the linker is the analysis). These works matter much more for the dynamic iteration. | ★★ (static) |
| Temporal specialization (USENIX Sec 2020) — cited | Phase-based allow-lists. | Nothing in AoN today. A natural extension is to retire blocks after init (§6, D-5). | ★★ |
| SysXCHG (CCS 2023) | Solves the problem that seccomp filters are inherited across `execve`. | The AoN region is read per image at exec, so the problem SysXCHG solves **does not arise**. This advantage over seccomp is real and the thesis does not state it. | ★★ |
| Shredder / Saffire (ACSAC 2018 / EuroS&P 2020) | Argument specialization per call site. | §7.3 notes that "a constraint that differs between callers needs finer sites". That is exactly Saffire's specialization, and Saffire's checks are skippable user code, which AoN would fix. | ★★ (L2 direction) |
| Nibbler (ACSAC 2019) | Shared-library debloating, then filtering. | Not applicable to static nolibc. Central to the dynamic iteration. | ★ (static) |
| Systrace / Janus / Ostia | Interposition. TOCTOU on arguments. | Cite for the TOCTOU argument of §4.1.6 and §7.3. | ★ |
| Forrest et al. (1996) | Learned anomaly detection. | A different paradigm. Background only. | ★ |
| C2C (CCS 2022) | Configuration-driven filters. | Orthogonal. | ★ |
| Draco (MICRO 2020) | Cost of system call checks. | Only for the cost discussion (AoN's cost is the extra entry, not the check). | ★ |
| Jenny (USENIX Sec 2022) | Syscall filtering for PKU compartments. Compares ptrace, seccomp and **Syscall User Dispatch**. | Relevant to "beyond system calls" (wrpkru) and to choosing interception mechanisms in the dynamic iteration. | ★★ |

### 2.2 Enforcing that a code block runs start to finish

| Work | Overlap | What the static iteration does differently | Rel. |
|---|---|---|---|
| **APEX** (USENIX Sec 2020) — *not cited* | **The closest conceptual match.** An EXEC flag is set only if the block starts at its first instruction and reaches its last without leaving, without interrupts and without modification. Any violation clears it. This is structurally the armed bit plus the check at the egress gate. | APEX: a hardware monitor watches the PC continuously, the target is a microcontroller, the result is consumed by a **remote verifier** after execution, and interrupts are forbidden. AoN: software in a commodity kernel, no PC monitoring (replaced by the **static condition**, which needs observation only at two points), the result is consumed by **the kernel before the protected operation**, and signals are allowed but disarm. | ★★★ |
| **SMART** (NDSS 2012), **VRASED** (USENIX Sec 2019) — *not cited* | "Entered only at its first instruction and left only from its last, run atomically", enforced in hardware. VRASED proves it formally. | Same differences as for APEX. VRASED's formal verification is a model for a **formal argument for AoN** (§6, D-8). | ★★★ |
| **TrustLite** (EuroSys 2014) — *not cited* | Controlled entry, with interrupts allowed and secure state save. | TrustLite saves the state in protected memory and resumes. AoN cannot protect a signal frame in user memory, so it disarms instead. This contrast justifies the signal rule, and it also suggests an alternative (§6, D-4). | ★★★ |
| **Fides** (CCS 2012), **Sancus** (USENIX Sec 2013), **SGX** — *not cited* | Program-counter-based access control: modules can be entered only at declared entry points. SGX's AEX/ERESUME handles interrupts. | They *prevent* an entry anywhere but an entry point, and they isolate memory from the OS. AoN *detects* it, at the egress gate, has no isolation, and trusts the kernel (the threat is in-process code reuse). Say explicitly that **AoN is entry-point discipline without isolation, realised as detection**. | ★★★ |
| Flicker / TrustVisor (2008/2010) | Isolated PALs entered only at defined points. | Heavy machinery (DRTM or a hypervisor). Cite as the extreme of the design space. | ★★ |
| **Bershad et al., restartable atomic sequences** (ASPLOS 1992) — *not cited* | The kernel guarantees that a registered user code range is never resumed partway: it rewinds to the start. | Not a security mechanism (the range is not protected against a jump in, only against preemption). It is the precedent for your **restart-at-ingress-gate** fix (§7.1). | ★★★ |
| **Linux rseq** — cited only in Future Work | Kernel-known user ranges and abort-on-preempt/signal. | The `rseq_cs` descriptor lives in **user memory** and can be changed at run time, so it would violate B3. Contrast with AoN's immutable ELF note. Move this into Chapter 3. | ★★★ |
| **ERIM** (USENIX Sec 2019) — cited | Call gates make `wrpkru` useful only inside a gate; binary scanning includes misaligned occurrences. | Your verifier (stray `ud2`) is the same idea as ERIM's scan. ERIM's check *after* `wrpkru` is a user-space detection that works because the instruction is unique. Your check-only egress gate (§7.4) follows the same logic. | ★★★ |
| **Hodor** (ATC 2019) | Scans code pages when they become executable; puts watchpoints on stray instructions that cannot be removed. | Direct design input for D4 and the verifier in the dynamic case (scan DSOs at `mmap`). | ★★ |
| Light-weight Contexts (OSDI 2016) | Kernel-mediated switches between in-process contexts. | Background. | ★ |
| **kBouncer** (USENIX Sec 2013), **ROPecker** (NDSS 2014) — *not cited* | The kernel checks how execution reached a sensitive call (LBR). | Heuristic and evadable, and they cover a path, not a block. AoN is exact for the block but blind to how it was reached. Table 4.1's row "hardware tracing / LBR" needs these citations. | ★★★ |
| **Griffin** (ASPLOS 2017), **FlowGuard** (HPCA 2017) — *not cited* | Kernel-enforced CFI from Intel PT, checked at system calls. | They need PT hardware and decoding, and they check the whole path. AoN needs no hardware and checks only the block. This is exactly the row of Table 4.1 the thesis argues against, so cite them there. **PathArmor** (CCS 2015, **verify**) belongs here too. | ★★★ |
| CET IBT / ARM BTI — cited | A landing pad at the target of indirect branches. | IBT already stops an *indirect jump* onto a `syscall` (no `endbr64` there). A shadow stack stops `ret`-based reuse. Together they cover vector A on CET hardware **if** user-space IBT is enabled. AoN does not care how the transfer happened (`ret`, `jmp`, SROP, signal frame) and needs no hardware. Make this argument explicitly: it is the question an examiner asks first. | ★★★ (already in) |

### 2.3 What is *already done* (static)

1. **Accepting system calls only from known sites, with the number bound to the site.** OpenBSD
   pinsyscalls (which also covers static binaries), Authenticated System Calls, and per-IP seccomp.
2. **A system call policy produced by the build or installation, with a kernel check that does
   not depend on the policy.** ASC (installer plus MAC) and OpenBSD static pinning (linker-emitted
   table).
3. **Refusing misaligned or out-of-region sites.** msyscall, pinsyscalls, ASC, and Linux Syscall
   User Dispatch (a region-based selector, though not a security mechanism; **verify**).
4. **The atomicity property itself** ("enter only at the first instruction, leave only from the
   last, interruption = violation"). SMART, VRASED, APEX, Sancus/TrustLite and SGX, in hardware.
5. **Kernel-known user code ranges with special preemption and signal semantics.** Restartable
   atomic sequences and rseq, without protection against tampering.
6. **Scanning the binary so that a privileged instruction occurs only at gate positions.** ERIM
   and Hodor, which is your verifier.
7. **Static linking plus `--gc-sections` as debloating.** Already in the thesis (§3.3.3).

### 2.4 What is *new* (static)

1. **The AoN primitive in a commodity OS kernel**: detection of partial execution by observing
   only two trapping gates, with no PC monitoring, no hardware support, and no change to the kernel
   sources (a loadable module).
2. **The static and dynamic conditions as the soundness argument for software atomicity**, and in
   particular the **signal rule**: disarm at delivery and never re-arm at `rt_sigreturn`. This is a
   clean treatment of SROP against atomic blocks. I know of no listed work that states it.
3. **The split between kernel and block**: the kernel guarantees execution and the block's code
   is the policy. It makes arbitrary straight-line user code *policy-bearing* for the kernel.
   APEX produces a proof for a remote party; AoN produces a precondition the kernel checks before
   the operation.
4. **The separation into egress gate kinds** (an operation-carrying `syscall` egress gate vs a
   check-only one), which generalises beyond system calls.
5. **The formal derivation** (behaviour model, P1–P4, D1–D4) of L1 from AoN plus bijective
   wrappers, including the honest result that this gives L1 *parity* with a per-site filter.

### 2.5 Verdict on the static iteration

- **Moderately innovative as a mechanism; not innovative as an L1 system call defense.** The
  thesis is internally honest (§4.1.6, §4.4). Its *framing* in §1.3 and §3.3.4 still suggests
  that pinsyscalls is weaker, while for L1 it is not, and the extra 400 ns per call buys no L1
  security over it.
- **What I recommend you change in the text:**
  1. Add a State of the Art section "Atomic and controlled-entry execution" (APEX, VRASED, SMART,
     TrustLite, Fides/Sancus/SGX, RAS/rseq, ERIM/Hodor), and add kBouncer, ROPecker, Griffin and
     FlowGuard to the "reaching the `syscall`" discussion and to Table 4.1.
  2. Add ASC next to pinsyscalls in §3.3.4 and Table 3.1.
  3. State in the introduction that the contribution at L1 is a *mechanism* that matches, rather
     than beats, site pinning, and that its value lies in being generic.
  4. Add the SysXCHG point (the AoN region is per image, so there is nothing to inherit across
     `execve`) as a real advantage over seccomp.

---

## 3. The dynamic iteration: what "transparent" can mean

The level of transparency decides how hard the iteration is and how novel it can be.

| Level | What stays unmodified | What changes | Precedent |
|---|---|---|---|
| **T0** | nothing (today: static, recompiled against aonlibc) | program build | the static iteration |
| **T1** | application binaries (dynamically linked, not recompiled) | a hardened `libc.so` + `ld.so` (AoN wrappers), the kernel module | OpenBSD libc + ld.so + pinsyscalls |
| **T2** | application binaries **and** the stock glibc | load-time rewriting of the system call sites of every loaded DSO into AoN blocks | zpoline (ATC 2023), lazypoline (DSN 2024), SaBRe (**verify** all three) |
| **T3** | the kernel too (mainline only) | — | not reachable: B1 needs the kernel to observe the gates |

T1 is the realistic target for a thesis iteration. T2 is the more novel one.

---

## 4. The dynamic iteration against the literature

### 4.1 Per-work relationship

| Work | What it gives the dynamic iteration | Already done there | Rel. |
|---|---|---|---|
| **OpenBSD msyscall/pinsyscalls + ld.so** | A deployed blueprint for a **dynamic, transparent (T1)** system call origin policy: the libc ELF carries a table of sites, `ld.so` registers it once, the kernel pins `ld.so` and static binaries itself, and registration is one-shot. | Site pinning for all of libc in every dynamically linked process. Policy from the build of libc. Transparent to applications. | ★★★ |
| **sysfilter**, **Confine**, **Chestnut** | How to compute the required set of a dynamically linked program: a call graph across the executable and its DSOs, or compile-time recording. | Per-program allow-lists for dynamic binaries, automatically, for thousands of Debian binaries. | ★★★ |
| **Nibbler**, **piece-wise compilation and loading** (Quach et al., cited), BlankIt (**verify**) | Load-time removal of unreachable library functions. Piece-wise records the **dependency graph of the library's functions in an ELF section at compile time**, which a loader then uses. This is exactly how to keep "the policy comes from the build" for a shared library. | Per-process library debloating at load time. | ★★★ |
| **Hodor**, **ERIM** | Scanning code pages when they become executable (`mmap`/`mprotect` with `PROT_EXEC`), which is how to extend the verifier and D4 to DSOs and `dlopen`. | In-process gates for `wrpkru`/`vmfunc` that work with shared libraries. | ★★★ |
| **zpoline / lazypoline** (**verify**) | Rewriting the `syscall` sites of unmodified binaries at load time (zpoline: `syscall` → `call *%rax` with a trampoline at 0; lazypoline: lazy rewriting driven by Syscall User Dispatch). This is the technique needed for T2. | Transparent interposition of system calls in unmodified glibc processes, for performance and tracing, not security. | ★★★ (if T2) |
| **Syscall User Dispatch** (Linux 5.11, **verify**) | A mainline, region-based "system calls from outside the range trap" mechanism. Jenny evaluates it. | Region-based origin checks in mainline, but not a security boundary (a user-writable selector). | ★★ |
| **Temporal specialization**, **SysXCHG** | Programs with phases (init vs serving) and exec chains are the common case once real dynamic programs are targeted. | Phase-aware and per-exec filters. | ★★ |
| **BASTION** | The obvious competitor for real dynamically linked programs (it was evaluated on NGINX, SQLite and vsftpd). | Context plus argument checks on sensitive system calls in real software. | ★★★ |
| **Draco** | The cost on system-call-heavy real workloads matters once dynamic real programs are measured (400 ns per call is visible in NGINX-like workloads). | Cheap checks. | ★★ |
| **rseq** | glibc registers rseq in every thread. An AoN-aware kernel must coexist with it, and rseq's abort-IP semantics are the model for restarting at the ingress gate. | — | ★★ |
| **Jenny** | Multi-threaded, signal-heavy, shared-library reality for in-process isolation plus system call filtering. Its catalogue of pitfalls (signals, `mmap`, `/proc/self/mem`, shared file descriptors) applies directly. | — | ★★ |

### 4.2 What is *already done* (dynamic)

1. A transparent (T1), loader-registered, kernel-enforced system call *origin* policy for dynamically
   linked processes: OpenBSD.
2. Per-program system call sets for dynamically linked binaries: sysfilter, Confine, Chestnut.
3. Load-time removal of unused shared-library code per process: piece-wise loading, Nibbler,
   BlankIt.
4. Load-time rewriting of system call sites in unmodified binaries (T2 tooling): zpoline,
   lazypoline.
5. Scanning newly executable pages for forbidden instructions: Hodor, ERIM.

So "AoN for `libc.so`, registered by the loader" is **not** new on its own. Without one of the
items in §4.3, the dynamic iteration would be "pinsyscalls on Linux, plus an ingress trap".

### 4.3 What can be *new* (dynamic): the open problems

1. **A per-process required set over shared library pages.** pinsyscalls pins the *whole* libc
   table in every process (thesis p. 31), so the intended-vs-mapped gap of dynamic linking
   (§2.3.2 of the thesis) remains. AoN can close it without copy-on-write of library pages: the
   code stays shared and identical, and the kernel keeps a **per-process set of enabled ingress
   gates**. Only the gates of required wrappers arm the thread; any other `ud2` in the region
   raises SIGILL. The required set would come from the build artefacts: the executable's imports,
   closed over a library dependency graph emitted at libc build time (as in piece-wise). That gives
   "required system calls" for dynamically linked code with **no filter and no per-program
   analysis tool**. None of the listed works combines a pinned or atomic site with a per-process
   enabled subset over shared code.
2. **B3 for code mapped after `execve`.** The static iteration reads one note before the first
   instruction. With DSOs, the regions appear when `ld.so` maps them, and with `dlopen` they appear
   at any time. You need a principled rule. Options:
   - the kernel parses the AoN note itself, from the *file*, at `mmap(PROT_EXEC)` through an LSM
     hook (`mmap_file`/`file_mprotect`);
   - accept only files that a trusted root vouches for (root-owned, fs-verity or IMA, or listed by
     build-id in the main executable's note);
   - refuse new regions after a "sealed" point (the end of `ld.so` start-up, or an explicit
     `prctl`), plus `mseal` on every region.

   This turns the "information fixed before the first instruction" of B3 into "information whose
   *source* is fixed before the first instruction". That reformulation is a contribution in itself.
3. **Compatibility with glibc as it is.** These are the blockers I checked on Debian 13 (glibc 2.41):
   - **Cancellable system calls use a generic site.** `read()` calls `__syscall_cancel` →
     `__syscall_cancel_arch` with the number passed as an argument, and the single-thread fast
     path loads it from the stack. That is a *generic wrapper*, and it breaks bijectivity (D1). An
     AoN glibc needs per-system-call cancellable blocks that still honour the cancellation range
     check of `__syscall_cancel_arch`. This interaction is new and has to be designed.
   - **`syscall(2)` is exported.** A program that imports `syscall` makes every number reachable.
     You need a policy (refuse it, or let the loader resolve `syscall` to a set of specialised
     wrappers when the number is a constant at the call site), and a measurement of how many
     Debian binaries import it.
   - **Restarted system calls** (`SA_RESTART`, `-ERESTARTSYS`, stop/continue) are everywhere in
     real programs. The static iteration's "refused restart" limitation becomes a blocker. The fix
     follows the restartable-atomic-sequence and rseq model: on a restart, the kernel rewinds `rip`
     to the **ingress gate** instead of the egress gate (the body is idempotent).
   - **The vDSO fallback `syscall`** (`clock_gettime` when the clocksource is not vDSO-capable,
     which is common in VMs). It is outside every AoN region, so D4 would refuse it. Either the
     kernel trusts its own vDSO sites, or the AoN libc never takes the fallback.
   - **`ld.so` issues 53 `syscall` instructions** before `main`. It needs its own AoN blocks (as
     OpenBSD pins `ld.so`).
   - Scale: glibc contains 423 aligned `syscall` instructions. 341 of them are directly preceded by
     a `mov $imm,%eax`, so most sites are already "almost blocks".
4. **T2 transparency for an unmodified glibc.** You would rewrite `mov $nr,%eax ; syscall` into an
   AoN block at load time, keeping the site in place or redirecting it to a trampoline in a
   generated AoN region. This has not been done for a security property that the kernel enforces.
   Watch out for in-place tricks that move the number through memory. For example,
   `ud2 ; push $nr ; pop %rax` fits in the 5 bytes of `mov` for nr < 128, but a sibling thread can
   race the stack slot, which breaks the registers-only guarantee. Trampolines are safer.

### 4.4 Verdict on the dynamic iteration

- **As "port the static design to `libc.so`": low novelty.** OpenBSD plus sysfilter cover it.
- **As "AoN for real dynamically linked Linux userland"**, with items 1–3 of §4.3 solved and
  measured on real programs (coreutils, NGINX, Redis, against BASTION and seccomp/sysfilter):
  **moderate to good systems novelty.** The per-process gate enablement over shared code, and B3
  for code mapped at run time, are the parts with no precedent in the list.
- **With T2 (unmodified glibc) on top: good novelty**, at a significant engineering cost.
- Even so, the guarantee stays **L1, equivalent to per-site pinning**. If the thesis is to be more
  than a better-engineered pinsyscalls, it needs a direction from §6.

---

## 5. Which papers to prioritise

### 5.1 Tier 1: read and cite in both iterations

| Paper | Why |
|---|---|
| **APEX** (USENIX Sec 2020) | The same structure as arm/check: the closest prior art for the primitive. |
| **VRASED** (USENIX Sec 2019) | Formally verified atomicity. The model for a formal argument. |
| **SMART** (NDSS 2012) | The original "first instruction in, last instruction out, atomic". |
| **Authenticated System Calls** (DSN 2005) | The closest prior art for the *application*: site-bound numbers, policy from the install or build, kernel check. |
| **OpenBSD pinsyscalls/msyscall** (already cited) | L1 equivalent (static) and the deployed blueprint (dynamic). |
| **Restartable atomic sequences** (ASPLOS 1992) + **rseq** | Kernel-known user ranges, restart semantics, and the contrast with B3. |
| **BASTION** (ASPLOS 2023, already cited) | The strongest competitor on syscall context. Argument integrity is the L2 path. |
| **ERIM** (already cited) + **Hodor** | Gate discipline, binary scanning, and pages that become executable at run time. |
| **Griffin** / **FlowGuard** / **kBouncer** / **ROPecker** | The kernel-side "how execution reached the `syscall`" alternatives of Table 4.1. |

### 5.2 Tier 2: cite

- TrustLite, Fides, Sancus, SGX: controlled entry, and interrupt handling as a contrast to the
  signal rule.
- Wagner & Dean, plus Wagner & Soto (mimicry, **verify**): to bound what L1 leaves.
- SysXCHG: the per-image policy advantage.
- Shredder/Saffire: per-call-site argument specialization (the L2 direction).
- Temporal specialization (already cited): phases.
- Jenny: interception methods and the pitfalls of real processes.

### 5.3 Tier 3: dynamic iteration specifically

- sysfilter and Confine (already cited), Chestnut, Nibbler, piece-wise (already cited), BlankIt (**verify**).
- zpoline, lazypoline, SaBRe (**verify**): only if you aim for T2.
- Syscall User Dispatch (**verify**).
- Draco: cost on real workloads.

### 5.4 Tier 4: background

Forrest et al., Systrace/Janus/Ostia (cite for TOCTOU), C2C, Flicker/TrustVisor, Light-weight
Contexts.

### 5.5 Not in the overview, worth checking (all **verify**)

- **SFIP: coarse-grained syscall-flow-integrity protection** (Canella et al., ~2022). It enforces
  syscall transitions **and syscall origins** (which sites may issue which system call) from the
  kernel, with the policy generated at compile time. If it is what I remember, it is very close to
  the L1 application on Linux.
- **PathArmor** (CCS 2015): context-sensitive CFI checked at system calls through LBR.
- **Mimicry attacks** (Wagner & Soto, CCS 2002).
- **zpoline** (USENIX ATC 2023), **lazypoline** (DSN 2024).
- **Syscall User Dispatch** (Linux 5.11 documentation).

---

## 6. Directions that would make the next iteration more innovative

The thesis's own analysis (§4.1.6) shows that for **policies on register values at the `syscall`**,
AoN is never stronger than a per-site filter. Every direction below is chosen to step outside that
equivalence, either by giving something *no check on the entry state can give*, or by solving a
problem that existing site-pinning cannot solve.

**D-1. Per-process gate enablement over shared libraries (core of the dynamic iteration).**
Shared, unmodified library pages, with a per-process set of enabled ingress gates computed from
build artefacts (the executable's imports plus a library dependency graph emitted when libc is
built). The result is "required system calls" for dynamically linked programs without seccomp and
without a per-program analysis tool. Evaluate it against sysfilter (precision of the set) and
pinsyscalls (size of the set). *Novel vs:* OpenBSD (which pins everything) and sysfilter (which
gives no site binding).

**D-2. B3 for run-time-mapped code, as a design principle.** Make the kernel derive regions from
*files* that a trusted root vouches for (fs-verity, IMA, build-id lists in the main binary), at
`mmap(PROT_EXEC)`, and seal them with `mseal`. Define a `dlopen` policy (allowed while not sealed,
or only for vouched files). This gives a clean answer to "can the attacker create a new AoN
region?", which today's static design avoids by having one note.

**D-3. Guaranteed side effects: the part seccomp cannot match.** An AoN body can *write memory*
before the operation, and the kernel then knows that the write happened. No entry-state check can
know that, because it would have to trust memory. Examples:
- **non-skippable BASTION-style argument shadowing**, where the block writes the shadow copy of
  the argument and then issues the system call, so the shadow cannot be bypassed by a jump;
- **non-skippable auditing or accounting** before sensitive system calls;
- **scrubbing secrets** before `execve` or `clone`.

The TOCTOU caveat still applies to what the *kernel* later reads, but "this store was executed"
is a new, kernel-checked fact. It is the clearest way to show that execution trust is *strictly*
more than site pinning.

**D-4. Lose the availability cost of the signal rule.** TrustLite and SGX keep the interrupted
state in protected storage and resume. For AoN, the kernel could save the register state of an
armed thread **in kernel memory** at delivery. At `rt_sigreturn` it would re-arm only if the
restored `rip` and registers equal the saved ones; otherwise it would stay disarmed. Alternatively,
it could rewind to the ingress gate (as RAS and rseq do). Either removes the "refused egress →
caller retries" rule, which real glibc programs (`SA_RESTART`, timers) would otherwise hit
constantly. Prove that it still defeats the SROP case of §4.2.6.

**D-5. Temporal AoN.** Retire gates after initialisation (an AoN `prctl` or a sealed "phase"
note), so that, for example, the `execve` or `socket` blocks stop arming after start-up. This is
temporal specialization without seccomp, and it makes the residual set smaller than any
whole-lifetime pinning. The design question is how to make retirement one-way and immune to the
attacker.

**D-6. Call-site-specific blocks (towards L2).** Saffire-style specialised wrappers, one AoN block
per call site with constant arguments pinned or masked in the body (for example, an `mprotect`
block that clears `PROT_EXEC` with an `and`, and `open` blocks with fixed flags). Saffire's checks
are skippable user code; as AoN bodies they are not. With shared libraries, the kernel's region
knowledge sidesteps the ASLR problem that makes per-IP seccomp impractical (§3.4 of the thesis).
This is a concrete step towards L2 that the static iteration leaves to future work.

**D-7. Beyond system calls: check-only gates for `wrpkru`.** You already outline this in §7.4.
A working prototype that replaces ERIM's binary rewriting with an AoN block around `wrpkru`, plus
an analysis of when detection *after* `wrpkru` is enough, would be the first demonstration that
the primitive is general and not specific to system calls.

**D-8. A formal model.** VRASED shows that atomicity properties can be formally verified. A small
model of AoN (a transition system over {armed, disarmed} × instruction pointer, with signals,
`rt_sigreturn`, restart, `clone` and `execve`) checked in TLA+ or a similar tool would turn
"sound under B4 and B5" into a proved statement. That is a strong and cheap contribution.

**D-9. Cut the cost of the ingress gate.** The 400 ns comes from the #UD exception path plus the
module's lock and allocation. For *system call* blocks specifically, the rejection of a
`syscall`-based ingress gate (§5.2.1: it clobbers `rax`, `rcx` and `r11`) matters less: the body
re-pins `rax`, and `rcx`/`r11` are clobbered by the egress `syscall` anyway. An ingress
`syscall`, accepted only at known ingress addresses, would go through the cheap system call path
(about 70–100 ns on your machine). A per-thread flag in `task_struct` space, with no global lock,
removes the module's share. Breaking the cost down (§7.2) and then halving it would also move
real-workload numbers into a range that can be compared with BASTION.

**Suggested combination for the dynamic thesis:** D-1 + D-2 + the glibc compatibility work of
§4.3 (including D-4 for restarts) as the systems core; D-3 or D-6 as the demonstration that
execution trust is more than site pinning; D-8 if time allows. That gives a story that the
literature does not already tell: *"kernel-enforced atomic blocks for dynamically linked Linux
userland, with a policy derived from build artefacts, and a guarantee that no entry-state filter
can express."*
