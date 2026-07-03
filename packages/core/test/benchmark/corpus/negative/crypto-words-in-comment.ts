// Comment-suppression regression test: this file contains NO crypto CODE — the
// only occurrences are inside comments, where an API name is followed by a space
// and a parenthesis: createECDH (deprecated since 2019). A purely lexical
// detector whose regex allows whitespace before "(" would misfire here, but the
// comment-aware filter (comments.ts) drops matches that start inside a comment.
// We label this file [] (expected zero) so the benchmark asserts precision stays
// at 1.000. See docs/validation/detection-benchmark.md.
export const note = "all classical crypto was removed in v3";
