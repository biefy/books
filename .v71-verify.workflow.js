export const meta = {
  name: 'verify-v71-citations',
  description: 'Verify every source citation and version-sensitive claim in both books against the live Linux v7.1 tree on devbox',
  whenToUse: 'Updating the books from 7.1-rc7 to final v7.1',
  phases: [
    { title: 'Verify', detail: 'one agent per chapter: extract claims, check each against ~/code/linux on devbox via ssh' },
    { title: 'Report', detail: 'collate per-chapter discrepancies into a single edit list' },
  ],
}

// Chapters that carry source citations or version-sensitive claims (from grep inventory).
const CHAPTERS = [
  // linux-net
  'linux-net/src/day01.md','linux-net/src/day02.md','linux-net/src/day03.md','linux-net/src/day04.md',
  'linux-net/src/day05.md','linux-net/src/day06.md','linux-net/src/day07.md','linux-net/src/day08.md',
  'linux-net/src/day09.md','linux-net/src/day10.md','linux-net/src/day11.md','linux-net/src/day12.md',
  'linux-net/src/day13.md','linux-net/src/day14.md','linux-net/src/day15.md','linux-net/src/day16.md',
  'linux-net/src/day17.md','linux-net/src/day18.md','linux-net/src/day19.md','linux-net/src/day20.md',
  'linux-net/src/day21.md','linux-net/src/day22.md','linux-net/src/day23.md','linux-net/src/day24.md',
  'linux-net/src/day25.md','linux-net/src/day26.md','linux-net/src/day27.md','linux-net/src/day28.md',
  'linux-net/src/day29.md','linux-net/src/day30.md','linux-net/src/README.md',
  // ebpf
  'ebpf/src/day01.md','ebpf/src/day02.md','ebpf/src/day03.md','ebpf/src/day04.md','ebpf/src/day05.md',
  'ebpf/src/day06.md','ebpf/src/day07.md','ebpf/src/day09.md','ebpf/src/day12.md','ebpf/src/day13.md',
  'ebpf/src/day15.md','ebpf/src/day17.md','ebpf/src/day18.md','ebpf/src/day19.md','ebpf/src/day20.md',
  'ebpf/src/day21.md','ebpf/src/day22.md','ebpf/src/day23.md','ebpf/src/day24.md','ebpf/src/day25.md',
  'ebpf/src/day27.md','ebpf/src/day28-30.md','ebpf/src/README.md',
]

const SSH = 'ssh -A4 fuyuanbie.dev.applink.azure.net'

const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    chapter: { type: 'string' },
    discrepancies: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          mdLine: { type: 'number', description: 'line number in the .md file where the claim appears' },
          claim: { type: 'string', description: 'the exact text/citation as written in the book' },
          kind: { type: 'string', enum: ['line-number', 'version-string', 'count', 'symbol-location', 'prose-fact', 'other'] },
          actual: { type: 'string', description: 'what the live v7.1 source actually shows' },
          severity: { type: 'string', enum: ['wrong', 'stale-approx', 'ok-note'] },
          suggestedFix: { type: 'string', description: 'concrete replacement text for the book' },
        },
        required: ['mdLine', 'claim', 'kind', 'actual', 'severity', 'suggestedFix'],
      },
    },
    citationsChecked: { type: 'number' },
    summary: { type: 'string' },
  },
  required: ['chapter', 'discrepancies', 'citationsChecked', 'summary'],
}

phase('Verify')

const results = await parallel(CHAPTERS.map(ch => () =>
  agent(
    `You are verifying one chapter of a technical book against the FINAL Linux kernel v7.1 source tree.

The kernel source is checked out at ~/code/linux on a remote devbox. Run commands there with:
  ${SSH} '<command>'
The tree is at tag v7.1 (Makefile VERSION=7 PATCHLEVEL=1 SUBLEVEL=0). The running kernel is also 7.1.0, and bpftool is v7.7.0, perf and bpftrace are installed.

CONTEXT — what changed between 7.1-rc7 (what the book was last checked against) and final v7.1:
272 commits total, but only 35 touch net/ or kernel/bpf/, and ALL 35 are small bug fixes (netfilter/xfrm/sctp/ipv6/rds UAF and NPD fixes) — none are refactors. The book's most-cited files (net/core/dev.c, net/core/gso.c, net/ipv4/ip_output.c, net/ipv4/tcp*.c) are UNTOUCHED rc7..final. The only book-relevant files with any churn: net/core/skbuff.c (net-zero, ~3 lines moved), net/core/gro.c (+5), net/core/sock.c (+5), include/net/sock.h (+1). So line numbers are expected to be stable; your job is to CONFIRM, and to catch the rare real drift plus any 7.0/7.x version strings and stale approximate counts. You can diff a specific cited file with:
  ${SSH} 'cd ~/code/linux && git diff --stat v7.1-rc7..v7.1 -- <path>'

The book chapter is the local file: ${ch}  (read it with your Read tool, relative to the books repo root /Users/fuyuanbie/code/books).

The book was previously fact-checked against 7.1-RC7. Your job: find anything that is now WRONG or STALE against FINAL v7.1.

Steps:
1. Read ${ch} fully.
2. Extract EVERY verifiable claim:
   - Explicit "file.c:NNN" or "file.h:NNN" citations (e.g. "net/core/skbuff.c:1552").
   - "line NNN in <file>" prose references.
   - Symbol/struct/function locations ("struct sk_buff lives at include/linux/skbuff.h", "defined in <file>").
   - Counts and approximations ("~7000 lines", "~128 reasons", "about 24 insns", "261 entries").
   - Version strings ("7.0", "7.x", "Linux 7.0 box", "on this 7.0 kernel") that refer to the TARGET kernel and should now read 7.1. (Do NOT flag historical version facts like "merged in 6.12" or "in-tree since 5.6" — those are correct history.)
3. For each citation, check it against the live tree. Useful commands:
   - Confirm a line: ${SSH} 'sed -n "1552p" ~/code/linux/net/core/skbuff.c'
   - Find where a symbol actually is now: ${SSH} 'grep -n "^struct sk_buff {" ~/code/linux/include/linux/skbuff.h'
   - Count lines: ${SSH} 'wc -l < ~/code/linux/net/core/skbuff.c'
   - Count enum entries: ${SSH} 'awk "/enum skb_drop_reason {/,/^};/" ~/code/linux/include/net/dropreason-core.h | grep -cE "^\\s+SKB_DROP_REASON_"'
   Always pass ABSOLUTE paths under ~/code/linux. Chain greps to LOCATE a symbol if the cited line is now off — report the new correct line.
4. For runtime/behavioral claims (verifier instruction counts, bpftool output format, command exit codes): you MAY run them on the devbox if cheap and safe (read-only). Do NOT run anything that mutates system state, loads persistent BPF, or changes sysctls. If a runtime claim needs a mutating repro, mark it 'ok-note' and describe what should be re-checked rather than running it.

Classify each discrepancy:
   - severity 'wrong': the cited line/count/version is factually off against v7.1 and would mislead a reader. Provide an exact suggestedFix.
   - severity 'stale-approx': an approximation that drifted but is still roughly right (e.g. "~7000" when it's 7522 — suggest "~7500"). Provide suggestedFix.
   - severity 'ok-note': verified correct, OR a runtime claim you could not safely re-capture (note what to verify on 7.1).

Only include entries in 'discrepancies' that need a book edit (severity 'wrong' or 'stale-approx') OR runtime claims needing manual recapture (ok-note). Do NOT list claims that verified perfectly — just count them in citationsChecked.

Be precise: suggestedFix must be the literal replacement string to drop into the markdown.`,
    { label: ch.replace('/src/', ':').replace('.md', ''), schema: FINDING_SCHEMA }
  )
))

phase('Report')

const all = results.filter(Boolean)
const withEdits = all.filter(r => r.discrepancies && r.discrepancies.length > 0)
const totalDisc = withEdits.reduce((n, r) => n + r.discrepancies.length, 0)
const totalChecked = all.reduce((n, r) => n + (r.citationsChecked || 0), 0)

log(`Verified ${all.length} chapters, ${totalChecked} claims checked, ${totalDisc} discrepancies across ${withEdits.length} chapters`)

return {
  chaptersVerified: all.length,
  totalClaimsChecked: totalChecked,
  totalDiscrepancies: totalDisc,
  chapters: withEdits,
}
