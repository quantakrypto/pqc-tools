// Negative bait (KNOWN FALSE POSITIVE): this file contains NO crypto calls — the
// only occurrences are inside this comment, where an API name is followed by a
// space and a parenthesis: createECDH (deprecated since 2019). A purely lexical
// detector whose regex allows whitespace before "(" will misfire here, because
// it cannot tell comment text from code. We label this file [] (expected zero)
// on purpose so the benchmark MEASURES and REPORTS that false positive instead
// of hiding it. See docs/validation/detection-benchmark.md.
export const note = "all classical crypto was removed in v3";
