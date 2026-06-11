export const meta = {
  name: 'observation-audit',
  description: 'Deep audit of every observation/experiment section across both books for pedagogical thoroughness and command correctness',
  whenToUse: 'Auditing the linux-net and ebpf books for under-developed observation sections',
  phases: [
    { title: 'Audit', detail: 'one auditor per chapter scores every observation section against the day01 bar' },
    { title: 'Verify', detail: 'adversarial skeptic re-reads each finding to kill false positives' },
    { title: 'Sweep', detail: 'one agent per known bpftrace bug pattern scans all 58 chapters' },
    { title: 'Synthesize', detail: 'per-book then executive synthesis into a prioritized report' },
  ],
}

// ---------------------------------------------------------------------------
// Chapter inventory (constructed deterministically — no fs access in scripts)
// ---------------------------------------------------------------------------
const pad = (n) => (n < 10 ? '0' + n : '' + n)
const CHAPTERS = []
for (let i = 1; i <= 30; i++) {
  const d = 'day' + pad(i)
  CHAPTERS.push({ id: 'ln-' + d, book: 'linux-net', path: 'linux-net/src/' + d + '.md' })
}
for (let i = 1; i <= 27; i++) {
  const d = 'day' + pad(i)
  CHAPTERS.push({ id: 'ebpf-' + d, book: 'ebpf', path: 'ebpf/src/' + d + '.md' })
}
CHAPTERS.push({ id: 'ebpf-day28-30', book: 'ebpf', path: 'ebpf/src/day28-30.md' })

// ---------------------------------------------------------------------------
// Shared knowledge injected into every agent
// ---------------------------------------------------------------------------
const RUBRIC = `
A "thoroughly laid out" observation/experiment section meets ALL of these. The GOLD STANDARD is
linux-net/src/day01.md (read lines 87-191 for reference) — the author just refined it to this bar:

1. CORRECT — every command runs as written on the target (Linux 7.x kernel, bpftrace v0.25, perf,
   bpftool, pahole, ip, tc, ethtool). No syntax or API errors. Probe arg names / struct fields match
   real kernel + BTF, not header macros.
2. PRODUCES OUTPUT — on the reader's likely-idle machine the command yields meaningful, NON-EMPTY
   output. If an idle box would show nothing (no packets, no drops, no connections), the section MUST
   first provide a load/trigger step. (day01 Obs3 fires a curl loop to provoke NO_SOCKET drops before
   tracing; day01 Obs2 starts a tcpdump so skb_clone actually fires.)
3. EXPECTED OUTPUT DESCRIBED — the reader is told what success looks like ("most packets have ~64
   bytes headroom", "NO_SOCKET near the top"). A command with no stated expected result is a finding.
4. EXPLAINS WHY / PITFALLS — the mechanism and any non-obvious gotcha is spelled out. (day01 explains
   why 'timeout 10' is required — sort/uniq buffer and Ctrl-C tears the pipe down before EOF; why
   '-w /dev/null'.) A bare "run this" with no why, when there IS a why, is a finding.
5. SETUP & CLEANUP — prerequisites are stated (tools, CONFIG_* options, a built vmlinux for pahole,
   background load) and any background process started is later stopped (e.g. pkill tcpdump).
6. TIES BACK TO THE CONCEPT — the observation visibly demonstrates the chapter's lesson and the prose
   connects the observed output back to it. A command that runs but teaches nothing about the day's
   topic is a finding.
7. CONSISTENT — matches conventions used in the rest of the books (probe style, helper usage, the
   kfree_skb_reason-over-kfree_skb preference, etc.).
`

const BUG_RULES = `
KNOWN SYSTEMATIC bpftrace/CLI bug patterns in these books (caught by running on a real kernel). Treat
any occurrence as a CORRECTNESS (critical) finding:

1. fentry:/fexit: probe args are 'args->FIELD', NEVER bare 'FIELD'. Inside an fentry block,
   'skb->len', 'skb->dev->name', 'skb->data' are rejected ("Unknown identifier: 'skb'"). Must be
   'args->skb->len' etc.
2. 'exit' must be written 'exit()'. Bare 'exit;' or 'exit }' => "Unknown identifier: 'exit'".
3. Pointer subtraction needs casts: 'skb->data - skb->head' errors ("- operator can not be used on
   uint8 *"). Use '(uint64)args->skb->data - (uint64)args->skb->head'.
4. '%pI4' / '%pI6' combined with '&args->...->field' is a syntax error in bpftrace 0.25
   ("unexpected builtin"). Idiomatic fix: 'ntop(args->...->daddr)' printed with '%s'. IPv6:
   'ntop(args->solicit->in6_u.u6_addr8)'.
5. bpftrace reads BTF field names, not CPP macros. 'args->flp4->flowi4_oif' fails (flowi4_oif is a
   #define); use the real field 'args->flp4->__fl_common.flowic_oif'.
6. Kernel arg names must match the real signature. e.g. ipv6_skip_exthdr's param is 'nexthdrp' (a
   u8 *), not 'nexthdr'; '*args->nexthdrp' is correct. Verify with the source / 'bpftrace -lv'.

IMPORTANT ENVIRONMENT NUANCE (do NOT flag as a book bug): on the Azure test kernel,
'fentry:ip_rcv' and 'fentry:netif_receive_skb' attach but never fire, while 'tcp_v4_rcv',
'icmp_rcv', and 'tracepoint:net:netif_receive_skb' do fire. That is environment-specific, not a
book defect — never recommend changing a probe target solely because "it didn't fire for me".
`

const CATEGORIES = [
  'broken-command',     // syntax/API error — will not run or errors out
  'wont-fire-or-empty', // runs but yields empty/no output on an idle system; missing load/trigger
  'no-expected-output', // reader is not told what success looks like
  'missing-why',        // mechanism / pitfall not explained where it matters
  'missing-setup',      // prerequisite tool / CONFIG / build / background load not stated
  'missing-cleanup',    // background process started but never stopped
  'weak-pedagogy',      // observation does not tie back to the chapter's concept
  'inconsistency',      // diverges from conventions used elsewhere in the books
  'other',
]

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const FINDINGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    chapter: { type: 'string' },
    chapterTopic: { type: 'string', description: 'one line: what this chapter teaches' },
    sectionsAudited: { type: 'integer' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          id: { type: 'string', description: 'e.g. ln-day03-f1' },
          section: { type: 'string', description: 'heading text of the section' },
          lineRange: { type: 'string', description: 'e.g. 139-167' },
          category: { type: 'string', enum: CATEGORIES },
          severity: { type: 'string', enum: ['critical', 'major', 'minor'] },
          problem: { type: 'string', description: 'precise statement of what is wrong/missing' },
          evidence: { type: 'string', description: 'the exact command or quoted text at fault' },
          suggestedFix: { type: 'string', description: 'concrete, specific fix the author can apply' },
          runtimeVerifiable: { type: 'boolean', description: 'true if a real-kernel run on the VM would confirm/refute it' },
        },
        required: ['id', 'section', 'lineRange', 'category', 'severity', 'problem', 'evidence', 'suggestedFix', 'runtimeVerifiable'],
      },
    },
  },
  required: ['chapter', 'chapterTopic', 'sectionsAudited', 'findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string' },
    verdict: { type: 'string', enum: ['confirmed', 'false-positive', 'uncertain'] },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reasoning: { type: 'string' },
    refinedFix: { type: 'string', description: 'corrected/sharpened fix, or restate the original if already right' },
  },
  required: ['id', 'verdict', 'confidence', 'reasoning', 'refinedFix'],
}

const SWEEP_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    pattern: { type: 'string' },
    violations: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          file: { type: 'string' },
          line: { type: 'string' },
          snippet: { type: 'string' },
          isRealViolation: { type: 'boolean' },
          note: { type: 'string' },
        },
        required: ['file', 'line', 'snippet', 'isRealViolation', 'note'],
      },
    },
  },
  required: ['pattern', 'violations'],
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------
const auditPrompt = (item) => `You are auditing ONE chapter of a hands-on Linux kernel book for the
QUALITY of its observation/experiment sections. The author believes many of these sections are not
thoroughly laid out and wants every weakness found.

FILE TO AUDIT (read it in full): ${item.path}
BOOK: ${item.book}

WHAT COUNTS AS AN OBSERVATION/EXPERIMENT SECTION: any section under headings like
"## Today's experiment", "## What to break", "### Observation N", or sub-sections like
"### Watch ...", "### Trace ...", "### Inspect ...", "### Force ...", "### Verify ...", AND every
fenced shell/bpftrace/perf/bpftool/ip/tc command block inside them. Do NOT audit the conceptual prose,
the "What to read" lists, the bullet-point summary, or the check question — focus on the things the
reader is told to RUN and OBSERVE.

${RUBRIC}

${BUG_RULES}

INSTRUCTIONS:
- Read the whole chapter first so you understand the concept the observations are meant to demonstrate.
- Examine EVERY runnable command and the prose around it against all 7 rubric dimensions.
- Be specific and adversarial. "Could be clearer" is not a finding; "the reader runs this on an idle
  box and sees zero output because nothing generates <X>, and no trigger step is given" is a finding.
- For each problem emit one finding with a concrete, applyable suggestedFix (give the actual corrected
  command or the exact sentence to add).
- Set runtimeVerifiable=true when only a real-kernel run could settle whether the command works/produces
  output; false for pure pedagogy/prose gaps.
- id format: "${item.id}-f1", "${item.id}-f2", ...
- It is fine to return zero findings if a chapter's observations already meet the day01 bar — do not
  invent problems. Quality over quantity, but miss nothing real.`

const verifyPrompt = (item, finding) => `You are an adversarial verifier. A chapter auditor produced the
finding below about ${item.path}. Your job is to KILL false positives and sharpen real ones — assume the
finding is wrong until the file proves it right.

Re-read the relevant lines of ${item.path} yourself (open the file). Then judge.

FINDING (JSON):
${JSON.stringify(finding, null, 2)}

${BUG_RULES}

Decide:
- "confirmed" — the problem is real as stated. Provide a refinedFix (the original fix if already correct,
  or a corrected/sharper version).
- "false-positive" — the section is actually fine, OR the "fix" would introduce a bug, OR the complaint is
  about an environment quirk that is NOT a book defect (see the ENVIRONMENT NUANCE above). Explain why.
- "uncertain" — genuinely cannot tell without running on a real kernel; set confidence=low and say what
  run would settle it.

Be especially careful with:
- "broken-command" claims: confirm the syntax is actually wrong for bpftrace v0.25 / the named tool, not
  just unfamiliar. If the auditor missed a real bug-pattern violation, still confirm.
- "wont-fire-or-empty" claims: distinguish a genuine missing trigger step (real) from an environment-only
  non-firing probe (false-positive).
Return strict JSON per the schema.`

const sweepPrompt = (rule, idx) => `You are doing a single-lens systematic sweep across BOTH books for ONE
specific bug pattern. Use grep/ripgrep over these files only:
  linux-net/src/day*.md   ebpf/src/day*.md

PATTERN #${idx + 1} TO HUNT:
${rule}

For every candidate match, open the surrounding lines to confirm whether it is a REAL violation (inside a
bpftrace fentry/fexit/kprobe block, actually run by the reader) versus a false hit (e.g. inside prose, a C
struct definition, a comment, or a context where it is correct). Report file as "book/src/dayNN.md" and a
line number. Set isRealViolation accordingly with a one-line note. Be exhaustive — this lens exists to catch
cross-chapter inconsistencies the per-chapter auditors rationalize away.`

const PATTERNS = [
  `Bare probe-arg dereference inside fentry:/fexit: blocks — any 'skb->', 'sk->', a struct pointer used
   without the 'args->' prefix inside an 'fentry:'/'fexit:' action block. (kprobe: blocks legitimately use
   'arg0'/'argN' or pt_regs, so judge by probe type.)`,
  `Bare 'exit' not written as 'exit()' — search for 'exit' followed by ';' or whitespace+'}' inside
   bpftrace one-liners/blocks.`,
  `Uncast pointer subtraction in bpftrace — 'X->data - X->head' or similar pointer-minus-pointer without a
   '(uint64)' cast on both operands.`,
  `'%pI4'/'%pI6' format used together with an '&args->' or '&...->' address-of argument in a bpftrace
   printf — should be 'ntop(...)' with '%s'.`,
  `bpftrace using a CPP-macro field name instead of the real BTF field — e.g. 'flowi4_oif', 'flowi4_*',
   or other '#define' aliases used as 'args->...->flowi4_oif'. Flag macro-looking field accesses.`,
  `Wrong/guessed kernel function argument names in fentry/fexit (e.g. 'args->nexthdr' where the real param
   is 'nexthdrp'). Flag any args-> field whose name you cannot match to a plausible real kernel parameter.`,
]

const bookSynthPrompt = (book, chaptersJson, sweepJson) => `You are writing the ${book} section of an
observation-section audit report for a Linux kernel book. You are given the VERIFIED findings (confirmed +
uncertain only; false-positives already removed) for every chapter, plus the relevant systematic-sweep hits.

Produce GitHub-flavored markdown with:
1. A short "## ${book} — patterns" subsection: the 3-8 systematic weaknesses that recur across this book's
   chapters (e.g. "N chapters never state expected output", "M observations need a load generator that is
   not provided"), each with the list of chapters affected.
2. A "### Per-chapter findings" subsection: for EACH chapter that has findings, a "#### <chapter>" block
   with its topic line, then findings as a checklist ordered critical -> major -> minor. Each item:
   "- [ ] **[severity/category]** _section (lines)_ — problem. **Fix:** refinedFix". Mark uncertain ones
   with "(needs VM run)". Skip chapters with no findings (just note them in one line at the end as clean).

Be faithful to the data — do not invent findings or drop real ones. Keep fixes concrete and copy-pasteable.

VERIFIED FINDINGS (JSON):
${chaptersJson}

SYSTEMATIC SWEEP HITS for context (JSON):
${sweepJson}`

const execPrompt = (statsJson, lnPatterns, ebpfPatterns, sweepSummary) => `You are writing the executive
summary of a deep audit of the observation/experiment sections across two hands-on Linux kernel books
(linux-net, 30 chapters; ebpf, 28 chapters). The bar is linux-net day01, which the author just refined so
every command works, expected output is described, and pitfalls (why timeout/why -w /dev/null) are explained.

Write GitHub-flavored markdown:
1. "## Executive summary" — 2-4 sentences on the overall health of the observation sections and the single
   most important theme.
2. "## By the numbers" — a compact table from the stats (total verified findings, by severity, by category,
   chapters with the most issues).
3. "## Systematic patterns (cross-cutting)" — the weaknesses that span BOTH books, synthesized from the two
   per-book pattern lists and the sweep. This is the heart of the report: name each pattern, why it hurts
   the reader, and roughly how many chapters it touches.
4. "## Prioritized roadmap" — an ordered worklist: which chapters/categories to fix first for maximum
   reader impact, framed like the day01 refinement (correctness bugs first, then missing triggers, then
   expected-output, then why/pitfalls, then polish).
5. "## How to verify the runtime findings" — one short paragraph: the runtimeVerifiable findings should be
   confirmed on the test VM (kernel 7.0, bpftrace v0.25) before/after fixing; note the env nuance that some
   fentry probes (ip_rcv, netif_receive_skb) don't fire there and that's not a book bug.

STATS (JSON): ${statsJson}

LINUX-NET PATTERNS:
${lnPatterns}

EBPF PATTERNS:
${ebpfPatterns}

SWEEP SUMMARY:
${sweepSummary}`

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------
log(`Auditing ${CHAPTERS.length} chapters across both books against the day01 bar.`)

// Kick off the systematic-bug sweep concurrently with the per-chapter pipeline.
const sweepPromise = parallel(
  PATTERNS.map((rule, idx) => () =>
    agent(sweepPrompt(rule, idx), { label: `sweep:p${idx + 1}`, phase: 'Sweep', schema: SWEEP_SCHEMA })
  )
)

// Per-chapter: audit -> verify each finding. Pipeline so verification of an early chapter
// runs while later chapters are still being audited.
const chapterResults = await pipeline(
  CHAPTERS,
  (item) => agent(auditPrompt(item), { label: `audit:${item.id}`, phase: 'Audit', schema: FINDINGS_SCHEMA }),
  async (audit, item) => {
    if (!audit) return { chapter: item.id, book: item.book, chapterTopic: '', findings: [] }
    const findings = audit.findings || []
    if (findings.length === 0) return { ...audit, book: item.book, findings: [] }
    const verified = await parallel(
      findings.map((f) => () =>
        agent(verifyPrompt(item, f), { label: `verify:${f.id}`, phase: 'Verify', schema: VERDICT_SCHEMA })
          .then((v) => ({ ...f, verification: v }))
          .catch(() => ({ ...f, verification: null }))
      )
    )
    return { ...audit, book: item.book, findings: verified.filter(Boolean) }
  }
)

const sweepResults = (await sweepPromise).filter(Boolean)

// Keep only confirmed + uncertain findings (drop verified false-positives).
const clean = chapterResults.filter(Boolean).map((c) => ({
  ...c,
  findings: (c.findings || []).filter((f) => {
    const v = f.verification
    return !v || v.verdict === 'confirmed' || v.verdict === 'uncertain'
  }).map((f) => ({
    ...f,
    finalSeverity: f.severity,
    refinedFix: (f.verification && f.verification.refinedFix) || f.suggestedFix,
    verdict: f.verification ? f.verification.verdict : 'unverified',
  })),
}))

// Compute deterministic stats.
const allFindings = clean.flatMap((c) => c.findings.map((f) => ({ ...f, chapter: c.chapter, book: c.book })))
const bySeverity = {}, byCategory = {}, byChapter = {}
let confirmedCount = 0, uncertainCount = 0, runtimeCount = 0
for (const f of allFindings) {
  bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1
  byCategory[f.category] = (byCategory[f.category] || 0) + 1
  byChapter[f.chapter] = (byChapter[f.chapter] || 0) + 1
  if (f.verdict === 'confirmed') confirmedCount++
  if (f.verdict === 'uncertain') uncertainCount++
  if (f.runtimeVerifiable) runtimeCount++
}
const stats = {
  totalFindings: allFindings.length,
  confirmed: confirmedCount,
  uncertain: uncertainCount,
  runtimeVerifiable: runtimeCount,
  bySeverity,
  byCategory,
  topChapters: Object.entries(byChapter).sort((a, b) => b[1] - a[1]).slice(0, 12),
  chaptersClean: clean.filter((c) => c.findings.length === 0).map((c) => c.chapter),
}

const sweepRealHits = sweepResults.flatMap((s) =>
  (s.violations || []).filter((v) => v.isRealViolation).map((v) => ({ pattern: s.pattern, ...v }))
)
log(`Audit complete: ${allFindings.length} verified findings (${confirmedCount} confirmed, ${uncertainCount} uncertain); ${sweepRealHits.length} systematic sweep hits.`)

// Per-book synthesis (barrier needs full picture; only 2 calls).
phase('Synthesize')
const lnChapters = clean.filter((c) => c.book === 'linux-net' && c.findings.length)
const ebpfChapters = clean.filter((c) => c.book === 'ebpf' && c.findings.length)
const lnSweep = sweepRealHits.filter((h) => (h.file || '').startsWith('linux-net'))
const ebpfSweep = sweepRealHits.filter((h) => (h.file || '').startsWith('ebpf'))

const [lnReport, ebpfReport] = await parallel([
  () => agent(bookSynthPrompt('linux-net', JSON.stringify(lnChapters), JSON.stringify(lnSweep)), { label: 'synth:linux-net', phase: 'Synthesize' }),
  () => agent(bookSynthPrompt('ebpf', JSON.stringify(ebpfChapters), JSON.stringify(ebpfSweep)), { label: 'synth:ebpf', phase: 'Synthesize' }),
])

// Extract a short pattern blurb from each book report for the exec agent (first ~1500 chars is the patterns section).
const lnPatternBlurb = (lnReport || '').slice(0, 2000)
const ebpfPatternBlurb = (ebpfReport || '').slice(0, 2000)
const sweepSummary = sweepResults.map((s) => `- ${s.pattern.split('\n')[0].trim()}: ${(s.violations || []).filter((v) => v.isRealViolation).length} real hits`).join('\n')

const execReport = await agent(execPrompt(JSON.stringify(stats), lnPatternBlurb, ebpfPatternBlurb, sweepSummary), { label: 'synth:executive', phase: 'Synthesize' })

return {
  stats,
  sweepRealHits,
  executive: execReport,
  linuxNetReport: lnReport,
  ebpfReport: ebpfReport,
  allFindings,
}
