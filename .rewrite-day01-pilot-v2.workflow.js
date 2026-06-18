export const meta = {
  name: 'rewrite-day01-pilot-v2',
  description: 'Pilot v2: rewrite linux-net Day 1 (sk_buff) as a self-contained chapter teaching all prerequisite background, verified against v7.1',
  whenToUse: 'Piloting the self-contained-chapter rewrite (corrected: draft agent writes the file directly)',
  phases: [
    { title: 'Research', detail: 'identify prerequisite concepts used-but-not-introduced; verify each against v7.1 devbox source' },
    { title: 'Draft', detail: 'one agent writes the self-contained chapter directly to the .md file' },
    { title: 'Verify', detail: 'parallel adversarial checks read the written file: citations, technical correctness, commands, pedagogy' },
    { title: 'Revise', detail: 'apply verifier findings to the file in place' },
  ],
}

const SSH = 'ssh -A4 fuyuanbie.dev.applink.azure.net'
const CHAPTER = '/Users/fuyuanbie/code/books/linux-net/src/day01.md'
const BACKUP = '/tmp/day01_rewrite_backup.md'

const GUARDRAILS = `STRICT RULES:
- NEVER run git commands (no checkout/reset/restore/stash/add/commit) — you are editing a live repo and must not touch version control.
- NEVER delete or move files. Only Read, Edit, Write the target chapter, and run read-only ssh/grep/sed commands.
- Use single-line ssh commands only (no multi-line, no $() command substitution).`

const DEVBOX = `The Linux v7.1 source tree is at ~/code/linux on a devbox. Run commands with: ${SSH} '<command>'
Tree is tag v7.1 (Makefile VERSION=7 PATCHLEVEL=1 SUBLEVEL=0); running kernel 7.1.0, bpftool v7.7.0, perf, bpftrace, clang 21. Always absolute paths under ~/code/linux.`

// ---- Phase 1: Research ----
phase('Research')

const GAP_SCHEMA = {
  type: 'object',
  properties: {
    gaps: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          concept: { type: 'string' },
          whereUsed: { type: 'string', description: 'phrase in the current chapter that leans on it without explanation' },
          whyNeeded: { type: 'string' },
          teachingPoints: { type: 'array', items: { type: 'string' } },
          v71Anchors: { type: 'array', items: { type: 'string' }, description: 'verified file:line/struct/field/constant anchors in v7.1' },
          suggestedDiagram: { type: 'string' },
        },
        required: ['concept', 'whereUsed', 'whyNeeded', 'teachingPoints', 'v71Anchors'],
      },
    },
    keepAsIs: { type: 'array', items: { type: 'string' }, description: 'existing elements to preserve verbatim (citations, experiments, check question)' },
  },
  required: ['gaps', 'keepAsIs'],
}

const research = await agent(
  `You are an expert Linux-kernel networking educator auditing one book chapter for SELF-CONTAINEDNESS.

${DEVBOX}
${GUARDRAILS}

Read the current chapter: ${CHAPTER}.

The book's problem (author's words): chapters are code-tour + experiment focused and assume background the reader lacks. Concrete example: the sk_buff chapter leans on the NIC RX descriptor ring (build_skb / napi_alloc_skb "wraps the driver's preallocated page", "per-CPU caching") but never introduces what a NIC ring / DMA is, so the reader must go elsewhere.

Find EVERY prerequisite concept this chapter uses-but-doesn't-teach. For Day 1 (sk_buff): NIC RX/TX descriptor rings + DMA; the slab allocator (kmalloc/kmem_cache) __alloc_skb uses; why memory splits into linear buffer + page fragments (kmalloc max-order, fragmentation, MM pages); the refcounting model behind skb_clone vs skb_copy (skb->users vs skb_shared_info.dataref); cache-line alignment / hot-cold field ordering; NET_SKB_PAD rationale. Only REAL dependencies — don't invent gaps.

GROUND each gap in real v7.1 source: verify struct names, fields, constants, line numbers on the devbox (confirm skb_shared_info has dataref; the fclone/head slab cache names in net/core/skbuff.c; MAX_SKB_FRAGS; NET_SKB_PAD value). Put verified facts in v71Anchors.

Also list existing strong elements to PRESERVE verbatim: the verified line citations, the bpftrace/perf experiments, the pahole lab, the check question.

Return structured output.`,
  { label: 'research:gaps', schema: GAP_SCHEMA }
)

log(`Identified ${research.gaps.length} background gaps`)

// ---- Phase 2: Draft (writes the file directly) ----
phase('Draft')

const gapsText = research.gaps.map((g, i) =>
  `### Gap ${i + 1}: ${g.concept}
- Leaned on at: ${g.whereUsed}
- Reader stuck because: ${g.whyNeeded}
- Must teach: ${g.teachingPoints.join('; ')}
- v7.1 anchors (verified): ${g.v71Anchors.join('; ')}
- Diagram idea: ${g.suggestedDiagram || '(none)'}`
).join('\n\n')

const draftSummary = await agent(
  `You are writing a self-contained rewrite of Day 1 of "Linux Network Subsystem in 30 Days" — a hands-on kernel-internals book in Head First style.

${DEVBOX}
${GUARDRAILS}

FIRST read these for content and voice:
- Current chapter (the one you will rewrite): ${CHAPTER}
- Sibling for voice/format: /Users/fuyuanbie/code/books/linux-net/src/day02.md
- Book intro: /Users/fuyuanbie/code/books/linux-net/src/README.md

YOUR TASK: rewrite Day 1 so a reader needs NO outside background. Weave the prerequisite concepts below in as proper teaching sections (not footnotes). The chapter may roughly DOUBLE in length — wanted. Full rewrite, but PRESERVE the verified technical content exactly.

BACKGROUND TO TEACH (v7.1-grounded):
${gapsText}

PRESERVE VERBATIM (copy faithfully):
${research.keepAsIs.map(k => '- ' + k).join('\n')}

STYLE (match the book):
- Head First voice: direct 2nd-person, "There are no Dumb Questions" Q&A blocks, "Bullet Points" summary, "Check question" with <details> reveal.
- Keep front-matter: the "> **Today's mission:**" line (bump the time estimate to match new length, ~110 min) and "> **Phase 1 starts here.**" note.
- Keep existing diagram refs where they still fit: ![sk_buff anatomy](diagrams/day01_skb_anatomy.png), ![pointer relationships](diagrams/day01_skb_pointers.png), ![sk_buff lifecycle](diagrams/day01_skb_lifecycle.png). For a NEW helpful diagram, insert a placeholder line: <!-- DIAGRAM-SUGGESTION: filename.png — description --> (do NOT reference a non-existent png).
- Teach intuition (the "why") BEFORE the concrete struct/function. Pedagogy over code-dumping.
- Keep sections: "What to read in the kernel", "What to break / observe", "Bullet Points", "Check question", "Tomorrow". Expand Bullet Points to cover new background.
- Do NOT alter verified line numbers (skbuff.h:886, skbuff.c:1552, __alloc_skb 672, __build_skb 488) — copy exactly.
- Every NEW concrete claim (struct field, cache name, constant, line) must be TRUE for v7.1 — verify on the devbox with a quick read-only ssh grep/sed before writing it. Do not guess.

OUTPUT MECHANISM (important):
1. Use your Write tool to write the COMPLETE rewritten chapter markdown to BOTH paths: first ${CHAPTER}, then a backup copy to ${BACKUP}. The content must start with "# Day 1 —" and be clean markdown (NO line-number prefixes).
2. After writing both files, return a 4-6 line summary: final line count, the gaps you wove in, and any claim you couldn't verify (should be none).

Do not return the chapter text itself — write it to the files.`,
  { label: 'draft:write' }
)

log(`Draft written: ${String(draftSummary).split('\n')[0].slice(0, 100)}`)

// ---- Phase 3: Verify (read the written file) ----
phase('Verify')

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    dimension: { type: 'string' },
    issues: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['blocker', 'major', 'minor'] },
          location: { type: 'string', description: 'exact quote/section in the chapter' },
          problem: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'location', 'problem', 'fix'],
      },
    },
    summary: { type: 'string' },
  },
  required: ['dimension', 'issues', 'summary'],
}

const checks = [
  { key: 'citations', prompt: `Read the chapter ${CHAPTER} (it was just rewritten — confirm it is the LONG self-contained version with new background sections; if it looks like the short original, report that as a single blocker and stop). Verify every kernel source citation and concrete claim against the v7.1 devbox: each file:line (skbuff.h:886, skbuff.c:1552, __alloc_skb 672, __build_skb 488), every struct/field in NEW sections (skb_shared_info.dataref, slab cache names, MAX_SKB_FRAGS, NET_SKB_PAD value, fclone cache), every constant. Use ${SSH} 'sed -n "Np" ~/code/linux/<file>' and grep. Flag mismatches as blocker/major with the correct value. ${GUARDRAILS}` },
  { key: 'correctness', prompt: `You are a skeptical senior kernel networking engineer. Read ${CHAPTER} and hunt for TECHNICALLY WRONG or misleading statements in the NEW background sections (NIC RX rings/DMA, slab allocator, page fragments/MM, refcounting model, cache-line/hot-cold). Be adversarial; scrutinize claims that "sound right". Settle disputes against v7.1 source: ${SSH} '...'. Give the correct explanation for each error. ${GUARDRAILS}` },
  { key: 'commands', prompt: `Validate every shell/bpftrace/perf/pahole command in ${CHAPTER} is correct and runnable on the 7.1 devbox. Check probe targets exist (e.g. ${SSH} 'sudo bpftrace -l "fentry:*:__alloc_skb"'). For cheap READ-ONLY commands you may run them. Do NOT run mutating commands (loading persistent BPF, changing sysctls, tcpdump that persists). Flag broken commands with fixes. ${GUARDRAILS}` },
  { key: 'pedagogy', prompt: `You are the book's editor. Read ${CHAPTER} against the goal: reader needs NO outside background. Judge: (1) Are previously-missing concepts (esp. the NIC RX ring) introduced BEFORE they're used? (2) Head First voice + structure intact (mission line, Dumb Questions, Bullet Points, Check question, Tomorrow)? (3) Does background build intuition before code, or just dump structs? (4) Anything over-long/repetitive? Calibrate voice against /Users/fuyuanbie/code/books/linux-net/src/day02.md. Concrete fixes per issue. ${GUARDRAILS}` },
]

const verdicts = await parallel(checks.map(c => () =>
  agent(c.prompt, { label: `verify:${c.key}`, schema: VERDICT_SCHEMA, phase: 'Verify' })
))

const allIssues = verdicts.filter(Boolean).flatMap(v => (v.issues || []).map(i => ({ ...i, dimension: v.dimension })))
const blockers = allIssues.filter(i => i.severity === 'blocker')
const majors = allIssues.filter(i => i.severity === 'major')
log(`Verification: ${blockers.length} blockers, ${majors.length} majors, ${allIssues.length - blockers.length - majors.length} minors`)

// ---- Phase 4: Revise ----
phase('Revise')

let reviseSummary = 'no issues to revise'
if (allIssues.length > 0) {
  const issuesText = allIssues.map(i =>
    `[${i.severity}/${i.dimension}] "${i.location}": ${i.problem}\n  FIX: ${i.fix}`
  ).join('\n\n')
  reviseSummary = await agent(
    `Revise the chapter ${CHAPTER} to fix these verification findings. Read the current file, apply each fix with Edit (preserve everything correct). If a fix needs a kernel fact, confirm it on the devbox (${SSH} '...') first — never guess. Prioritize blockers and majors. After fixing, also overwrite ${BACKUP} with the corrected version. Reply with a 4-line summary of changes.
${GUARDRAILS}

FINDINGS:
${issuesText}`,
    { label: 'revise:apply' }
  )
}

return {
  chapter: 'linux-net/src/day01.md',
  gapsFilled: research.gaps.map(g => g.concept),
  draftSummary: String(draftSummary).slice(0, 400),
  verification: { blockers: blockers.length, majors: majors.length, total: allIssues.length },
  reviseSummary: String(reviseSummary).slice(0, 400),
  diagramSuggestions: research.gaps.filter(g => g.suggestedDiagram).map(g => ({ concept: g.concept, diagram: g.suggestedDiagram })),
  note: 'Pilot v2. Review the rewritten chapter before scaling. Backup at /tmp/day01_rewrite_backup.md.',
}
