// Production self-contained-rewrite workflow.
// Driven per-wave: pass args = { book, chapters: ["day02", ...] }.
// Each chapter runs an independent pipeline: Research -> Draft -> Diagrams -> Verify -> Revise.
export const meta = {
  name: 'rewrite-chapters-selfcontained',
  description: 'Rewrite book chapters as self-contained teaching texts (background woven in, new Graphviz diagrams, re-verified against v7.1)',
  whenToUse: 'Scaling the self-contained rewrite across remaining chapters, one wave at a time',
  phases: [
    { title: 'Research', detail: 'per chapter: find prerequisite concepts used-but-not-introduced; ground in v7.1' },
    { title: 'Draft', detail: 'per chapter: write the self-contained rewrite directly to the .md (with diagram placeholders)' },
    { title: 'Diagrams', detail: 'per chapter: author + render Graphviz .dot for each placeholder, wire PNGs in' },
    { title: 'Verify', detail: 'per chapter: parallel adversarial checks (citations, correctness, commands, pedagogy)' },
    { title: 'Revise', detail: 'per chapter: apply findings in place' },
  ],
}

const SSH = 'ssh -A4 fuyuanbie.dev.applink.azure.net'
const BOOK = (args && args.book) || 'linux-net'
const CHAPTERS = (args && args.chapters) || []
const ROOT = '/Users/fuyuanbie/code/books'
const SRCDIR = `${ROOT}/${BOOK}/src`
const DIAGDIR = `${SRCDIR}/diagrams`

const DEVBOX = `The Linux v7.1 source tree is at ~/code/linux on a devbox. Run commands with: ${SSH} '<command>'
Tree is tag v7.1 (Makefile VERSION=7 PATCHLEVEL=1 SUBLEVEL=0); running kernel 7.1.0, bpftool v7.7.0, perf, bpftrace, clang 21, veristat at ~/code/linux/tools/testing/selftests/bpf/veristat. Always absolute paths under ~/code/linux. Single-line ssh only (no multi-line, no $() substitution).`

const GUARDRAILS = `STRICT RULES:
- NEVER run git commands (no checkout/reset/restore/stash/add/commit/rm). You edit a live repo; do not touch version control.
- NEVER delete or move existing files. Only Read/Edit/Write the target chapter + new diagram files, and run read-only ssh/grep/sed plus the 'dot' renderer.
- Single-line ssh commands only.`

const CROSSREF = `CROSS-REFERENCING: This is the ${BOOK} book. Day 1 (linux-net) already teaches: NIC RX descriptor rings + DMA, the slab allocator, pages/fragmentation, the sk_buff two-refcount model, and CPU cache lines. Earlier chapters teach their own topics. When THIS chapter depends on a concept an EARLIER chapter already taught, do NOT re-teach it in full — give a one-line refresher and cross-reference (e.g. "recall the RX descriptor ring from Day 1"). Only teach NEW prerequisite background that no earlier chapter covers. The goal is a reader who started at Day 1 needs nothing external — not that every chapter repeats the whole book.`

const DIAGRAM_RULES = `GRAPHVIZ DIAGRAM RULES (the only renderer available is 'dot'):
- Author each diagram as a Graphviz .dot file in ${DIAGDIR}/src/ named <chapterId>_<slug>.dot, render with: dot -Tpng ${DIAGDIR}/src/<name>.dot -o ${DIAGDIR}/<name>.png
- Do NOT use d2 or mermaid (not installed). Match the book palette: descriptors/structs #dbeafe (blue), buffers/data #fef3c7 (amber), shared/frags/notes #dcfce7 (green), warnings #fee2e2 (red), accent #e9d5ff (purple). Use fontname="Monaco" for code-ish node labels, "Helvetica" for titles.
- CRITICAL escaping: inside shape=record labels, NEVER use \\l or \\n escape sequences (they render literally). Use plain text; for multi-line in a record cell use \\n ONLY as an actual newline char, not the backslash-n token. In shape=note/box labels, real \\l (left-justify) is fine. After rendering, you MUST view the PNG with your Read tool and confirm it is not garbled (no literal "\\l"/"\\n" text, no overlapping labels, legible). Re-edit and re-render until clean.
- NO DUPLICATE SOURCES: only author NEW diagrams (slugs that came from a DIAGRAM-SUGGESTION placeholder you are replacing). Before creating ${DIAGDIR}/src/<name>.dot, check that NO source already exists for that <name> in any format: run 'ls ${DIAGDIR}/src/<name>.*'. If a .d2, .mmd, OR .dot already exists for that exact name, that diagram is pre-existing — DO NOT create a second source for it and DO NOT re-render it; leave it and its PNG completely alone. render-diagrams.sh renders .d2, then .mmd, then .dot to the same PNG, so two sources with one basename silently clobber each other. You only ever touch the brand-new slugs introduced by this chapter's placeholders.`

// Run each chapter as an independent pipeline. No barrier between chapters.
const results = await pipeline(
  CHAPTERS,

  // ---- Stage 1: Research (per chapter) ----
  async (chapterId) => {
    const path = `${SRCDIR}/${chapterId}.md`
    const GAP_SCHEMA = {
      type: 'object',
      properties: {
        chapterId: { type: 'string' },
        title: { type: 'string' },
        gaps: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              concept: { type: 'string' },
              whereUsed: { type: 'string' },
              teachingPoints: { type: 'array', items: { type: 'string' } },
              v71Anchors: { type: 'array', items: { type: 'string' } },
              suggestedDiagram: { type: 'string' },
              crossRefInstead: { type: 'string', description: 'if an earlier chapter already covers this, name it here and it becomes a one-line refresher not a full section' },
            },
            required: ['concept', 'whereUsed', 'teachingPoints', 'v71Anchors'],
          },
        },
        keepAsIs: { type: 'array', items: { type: 'string' } },
      },
      required: ['chapterId', 'gaps', 'keepAsIs'],
    }
    const research = await agent(
      `You are an expert Linux-kernel educator auditing one chapter of the "${BOOK}" book for SELF-CONTAINEDNESS.
${DEVBOX}
${GUARDRAILS}
${CROSSREF}

Read the current chapter: ${path}. Also read the book intro ${SRCDIR}/README.md once for scope.

The book's problem: chapters are code-tour + experiment focused and assume background the reader lacks (e.g. the original sk_buff chapter used NIC RX rings without ever introducing them). Find EVERY prerequisite concept THIS chapter uses-but-doesn't-teach AND that no earlier chapter already taught. For each, list the specific teaching points and GROUND them in real v7.1 source — verify struct names, fields, constants, and line numbers on the devbox; put verified facts in v71Anchors. If a gap is already covered by an earlier chapter, set crossRefInstead instead of writing a full section.

Also list existing strong elements to PRESERVE verbatim: verified file:line citations, experiments/labs, the check question.
Return structured output.`,
      { label: `research:${chapterId}`, schema: GAP_SCHEMA, phase: 'Research' }
    )
    return { chapterId, path, research }
  },

  // ---- Stage 2: Draft (writes file directly) ----
  async (prev) => {
    const { chapterId, path, research } = prev
    const gapsText = research.gaps.map((g, i) =>
      `### Gap ${i + 1}: ${g.concept}${g.crossRefInstead ? ' [CROSS-REF, not a full section: ' + g.crossRefInstead + ']' : ''}
- Leaned on at: ${g.whereUsed}
- Teach: ${g.teachingPoints.join('; ')}
- v7.1 anchors: ${g.v71Anchors.join('; ')}
- Diagram idea: ${g.suggestedDiagram || '(none)'}`
    ).join('\n\n')

    await agent(
      `You are writing a self-contained rewrite of ${chapterId} of the "${BOOK}" book (Head First style, hands-on kernel internals).
${DEVBOX}
${GUARDRAILS}
${CROSSREF}

FIRST read: the current chapter ${path}; a sibling for voice (${SRCDIR}/day02.md or another nearby day); and the gold-standard already-rewritten example ${ROOT}/linux-net/src/day01.md (study how it weaves background in, intuition-before-struct, and how it places diagrams).

TASK: rewrite ${chapterId} so a reader who started at Day 1 needs NO outside background. Weave the NEW prerequisite concepts below in as proper teaching sections (intuition first, then the concrete v7.1 struct/function). For CROSS-REF gaps, give only a one-line refresher + pointer. The chapter may roughly DOUBLE; that's fine. Full rewrite, but PRESERVE verified technical content exactly.

BACKGROUND TO TEACH (v7.1-grounded):
${gapsText}

PRESERVE VERBATIM:
${research.keepAsIs.map(k => '- ' + k).join('\n')}

STYLE (match day01.md and the book):
- Head First voice; keep "> **Today's mission:**" and any "> **Phase N starts here.**" front-matter (bump the time estimate for new length).
- Keep existing diagram image refs that still fit. For each NEW diagram, insert a placeholder line EXACTLY of the form:
  <!-- DIAGRAM-SUGGESTION: ${chapterId}_<slug>.png — <one-line description of what to draw> -->
  (the next phase renders these). Place it in the section it illustrates.
- Keep sections: "There are no Dumb Questions" Q&A (if present), "What to read in the kernel", "What to break/observe" or "Today's experiment", "Bullet Points", "Check question" with <details>, "Tomorrow".
- Do NOT alter verified line numbers — copy them exactly.
- Every NEW concrete claim must be TRUE for v7.1 — verify on the devbox with a read-only ssh grep/sed before writing. Do not guess.

OUTPUT: use Write to save the COMPLETE rewritten chapter (clean markdown, starts with "# ", NO line-number prefixes) to ${path}. Then return a 4-line summary: final line count, gaps woven, diagram placeholders inserted (list their slugs), any claim you couldn't verify (should be none).`,
      { label: `draft:${chapterId}`, phase: 'Draft' }
    )
    return prev
  },

  // ---- Stage 3: Diagrams (author + render + wire in) ----
  async (prev) => {
    const { chapterId, path } = prev
    const diagramSummary = await agent(
      `You are creating the diagrams for the just-rewritten chapter ${path}.
${GUARDRAILS}
${DIAGRAM_RULES}

Steps:
1. Read ${path} and find every line of the form <!-- DIAGRAM-SUGGESTION: ${chapterId}_<slug>.png — <desc> -->.
2. For EACH placeholder: author a Graphviz .dot file at ${DIAGDIR}/src/${chapterId}_<slug>.dot that draws what the description asks, in the book palette. Study an existing source for style, e.g. ${DIAGDIR}/src/day01_rx_ring.dot or ${ROOT}/linux-net/src/diagrams/src/day01_two_allocators.dot.
3. Render it: dot -Tpng ${DIAGDIR}/src/${chapterId}_<slug>.dot -o ${DIAGDIR}/${chapterId}_<slug>.png
4. VIEW the resulting PNG with your Read tool. If it is garbled (literal \\l or \\n text, overlapping/truncated labels, illegible), fix the .dot and re-render until clean.
5. Replace the placeholder comment line in ${path} with a markdown image ref: ![<short alt>](diagrams/${chapterId}_<slug>.png)

When all placeholders are done, confirm 0 remain (grep) and every referenced png exists. Return a summary: how many diagrams created and their filenames.`,
      { label: `diagram:${chapterId}`, phase: 'Diagrams' }
    )
    return { ...prev, diagramSummary }
  },

  // ---- Stage 4: Verify (parallel adversarial checks) ----
  async (prev) => {
    const { chapterId, path } = prev
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
              location: { type: 'string' },
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
      { key: 'citations', prompt: `Read ${path} (confirm it is the LONG self-contained rewrite, not the short original — if short, report one blocker and stop). Verify every kernel source citation and concrete claim against the v7.1 devbox: each file:line, every struct/field/constant in NEW sections. Use ${SSH} 'sed -n "Np" ~/code/linux/<file>' and grep. Flag mismatches with the correct value. ${GUARDRAILS}` },
      { key: 'correctness', prompt: `Skeptical senior kernel engineer: read ${path} and hunt for TECHNICALLY WRONG/misleading statements in the NEW background sections. Be adversarial; settle disputes against v7.1 source on the devbox (${SSH} '...'). Give the correct explanation per error. ${GUARDRAILS}` },
      { key: 'commands', prompt: `Validate every shell/bpftrace/perf/bpftool/pahole command in ${path} is correct on the 7.1 devbox. Check probe targets exist (${SSH} 'sudo bpftrace -l "..."'). Run only cheap READ-ONLY commands; never mutate (no persistent BPF load, no sysctl writes, no lasting tcpdump). Flag broken commands with fixes. ${GUARDRAILS}` },
      { key: 'pedagogy', prompt: `Book editor: read ${path} against the goal (reader needs NO outside background, but earlier-taught concepts are cross-referenced not repeated). Judge: new concepts introduced before use? Head First voice + structure intact? Intuition before code? Diagrams present and placed well (image refs, not leftover placeholders)? Anything over-long/repetitive or redundant with earlier chapters? Calibrate against ${ROOT}/linux-net/src/day01.md. Concrete fixes. ${GUARDRAILS}` },
    ]
    const verdicts = await parallel(checks.map(c => () =>
      agent(c.prompt, { label: `verify:${chapterId}:${c.key}`, schema: VERDICT_SCHEMA, phase: 'Verify' })
    ))
    const allIssues = verdicts.filter(Boolean).flatMap(v => (v.issues || []).map(i => ({ ...i, dimension: v.dimension })))
    return { ...prev, allIssues }
  },

  // ---- Stage 5: Revise ----
  async (prev) => {
    const { chapterId, path, allIssues, diagramSummary } = prev
    const blockers = allIssues.filter(i => i.severity === 'blocker')
    const majors = allIssues.filter(i => i.severity === 'major')
    let reviseSummary = 'no issues'
    if (allIssues.length > 0) {
      const issuesText = allIssues.map(i => `[${i.severity}/${i.dimension}] "${i.location}": ${i.problem}\n  FIX: ${i.fix}`).join('\n\n')
      reviseSummary = await agent(
        `Revise ${path} to fix these verification findings. Read the current file, apply each with Edit (preserve correct content). If a fix needs a kernel fact, confirm on the devbox (${SSH} '...') first — never guess. If a diagram fix is needed, re-edit its .dot in ${DIAGDIR}/src/ and re-render with dot, then view the PNG. Prioritize blockers and majors. Reply with a 4-line summary.
${GUARDRAILS}
${DIAGRAM_RULES}

FINDINGS:
${issuesText}`,
        { label: `revise:${chapterId}`, phase: 'Revise' }
      )
    }
    log(`${chapterId}: ${blockers.length} blockers, ${majors.length} majors, ${allIssues.length} total issues; diagrams: ${String(diagramSummary).slice(0, 60)}`)
    return {
      chapterId,
      verification: { blockers: blockers.length, majors: majors.length, total: allIssues.length },
      reviseSummary: String(reviseSummary).slice(0, 300),
    }
  }
)

const done = results.filter(Boolean)
return {
  book: BOOK,
  chaptersProcessed: done.map(r => r.chapterId),
  totals: {
    blockers: done.reduce((n, r) => n + (r.verification?.blockers || 0), 0),
    majors: done.reduce((n, r) => n + (r.verification?.majors || 0), 0),
  },
  perChapter: done,
  note: 'Wave complete. Review diffs before committing this wave.',
}
