import Papa from "papaparse";

// Default patterns to use if none are provided in the configuration
export const defaultPatterns = [
  ['Phone number', '\\b\\d{3} \\d{2} \\d{2} \\d{2}\\b'],
  ['Credit card number', '\\b(?:\\d[ -]*?){13,16}\\b'],
  ['Email address', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b']
];

// For PRs: use provided patterns or fallback to defaultPatterns
export function detectSensitiveDataForPR(file, content, context, patterns) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detectedMatches = [];
  for (const [label, pattern] of patternsToUse) {
    const regex = new RegExp(pattern, "g");
    const matches = content.match(regex);
    if (matches) {
      context.log.warn(`${label} found in ${file}: ${matches.join(', ')}`);
      detectedMatches.push(...matches);
    }
  }
  return detectedMatches;
}

export function detectSensitiveDataTxt(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  for (const [label, pattern] of patternsToUse) {
    const regex = new RegExp(pattern, "g");
    const matches = content.match(regex);
    if (matches) {
      const filteredMatches = matches.filter(match => !exclusions.includes(match));
      if (filteredMatches.length > 0) {
        detected.push({ label, matches: filteredMatches });
      }
    }
  }
  return detected;
}

export function detectSensitiveDataCsv(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  const { data } = Papa.parse(content, { header: false, skipEmptyLines: true });

  for (const row of data) {
    const rowString = row.join(',');
    for (const [label, pattern] of patternsToUse) {
      const regex = new RegExp(pattern, "g");
      const matches = rowString.match(regex);
      if (matches) {
        const filteredMatches = matches.filter(match => !exclusions.includes(match));
        if (filteredMatches.length > 0) {
          detected.push({ label, matches: filteredMatches });
        }
      }
    }
  }
  return detected;
}