import Papa from "papaparse";
import { defaultPatterns } from "./patterns.js";


/**
 * Detects sensitive data for PRs in various file types.
 * @param {string} file - File name.
 * @param {string} content - File content.
 * @param {object} context - Probot context object.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @param {string} type - File type.
 * @param {Array} fileTypes - Supported file types.
 * @returns {Array} - Array of detected vulnerabilities.
 */
export function detectSensitiveDataForPR(file, content, context, patterns, exclusions, type, fileTypes) {

  
  const fileExt =  file.split('.').pop().toLowerCase();
  if (!fileTypes.includes(fileExt)) {
    context.log.info(`File extension "${fileExt}" for file "${file}" is not enabled in configuration. Skipping.`);
    return [];
  }

  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detectedMatches = [];


  const filterExclusions = (matches) =>
    exclusions && exclusions.length > 0
      ? matches.filter(match => !exclusions.includes(match))
      : matches;

  // Logic selection according to file type
  if (type === "csv") {
    const { data } = Papa.parse(content, { header: false, skipEmptyLines: true });
    for (const row of data) {
      const rowString = row.join(",");
      for (const [label, pattern] of patternsToUse) {
        const regexPattern = pattern.replace(/\\\\/g, '\\');
        const regex = new RegExp(regexPattern, "g");
        const matches = rowString.match(regex);
        if (matches) {
          const filteredMatches = filterExclusions(matches);
          if (filteredMatches.length > 0) {
            context.log.warn(`${label} found in ${file}: ${filteredMatches.join(', ')}`);
            detectedMatches.push({ label, matches: filteredMatches });
          }
        }
      }
    }
  } else if (type === "json") {
    let jsonObj;
    try {
      jsonObj = JSON.parse(content);
    } catch (e) {
      return detectedMatches;
    }
    const jsonString = JSON.stringify(jsonObj);
    for (const [label, pattern] of patternsToUse) {
      const regexPattern = pattern.replace(/\\\\/g, '\\');
      const regex = new RegExp(regexPattern, "g");
      const matches = jsonString.match(regex);
      if (matches) {
        const filteredMatches = filterExclusions(matches);
        if (filteredMatches.length > 0) {
          context.log.warn(`${label} found in ${file}: ${filteredMatches.join(', ')}`);
          detectedMatches.push({ label, matches: filteredMatches });
        }
      }
    }
  } else if (type === "yaml" || type === "yml") {
    for (const [label, pattern] of patternsToUse) {
      const regexPattern = pattern.replace(/\\\\/g, '\\');
      const regex = new RegExp(regexPattern, "g");
      const matches = content.match(regex);
      if (matches) {
        const filteredMatches = filterExclusions(matches);
        if (filteredMatches.length > 0) {
          context.log.warn(`${label} found in ${file}: ${filteredMatches.join(', ')}`);
          detectedMatches.push({ label, matches: filteredMatches });
        }
      }
    }
  } else  {
    for (const [label, pattern] of patternsToUse) {
      const regexPattern = pattern.replace(/\\\\/g, '\\');
      const regex = new RegExp(regexPattern, "g");
      const matches = content.match(regex);
      if (matches) {
        const filteredMatches = filterExclusions(matches);
        if (filteredMatches.length > 0) {
          context.log.warn(`${label} found in ${file}: ${filteredMatches.join(', ')}`);
          detectedMatches.push({ label, matches: filteredMatches });
        }
      }
    }
  }
  return detectedMatches;
}

/**
 * Detects sensitive data in .txt files.
 * @param {string} content - File content.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Array} - Array of detected vulnerabilities.
 */
export function detectSensitiveDataTxt(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  for (const [label, pattern] of patternsToUse) {
    const regexPattern = pattern.replace(/\\\\/g, '\\');
    const regex = new RegExp(regexPattern, "g");
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

/**
 * Detects sensitive data in .csv files.
 * @param {string} content - File content.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Array} - Array of detected vulnerabilities.
 */
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

/**
 * Detects sensitive data in .md files.
 * @param {string} content - File content.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Array} - Array of detected vulnerabilities.
 */
export function detectSensitiveDataMd(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  for (const [label, pattern] of patternsToUse) {
    const regexPattern = pattern.replace(/\\\\/g, '\\');
    const regex = new RegExp(regexPattern, "g");
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

/**
 * Detects sensitive data in .json files.
 * @param {string} content - File content.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Array} - Array of detected vulnerabilities.
 */
export function detectSensitiveDataJson(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  let jsonObj;
  try {
    jsonObj = JSON.parse(content);
  } catch (e) {
    return detected;
  }
  const jsonString = JSON.stringify(jsonObj);
  for (const [label, pattern] of patternsToUse) {
    const regexPattern = pattern.replace(/\\\\/g, '\\');
    const regex = new RegExp(regexPattern, "g");
    const matches = jsonString.match(regex);
    if (matches) {
      const filteredMatches = matches.filter(match => !exclusions.includes(match));
      if (filteredMatches.length > 0) {
        detected.push({ label, matches: filteredMatches });
      }
    }
  }
  return detected;
}

/**
 * Detects sensitive data in .yaml or .yml files.
 * @param {string} content - File content.
 * @param {Array} patterns - Patterns to detect.
 * @param {Array} exclusions - Exclusions to ignore.
 * @returns {Array} - Array of detected vulnerabilities.
 */
export function detectSensitiveDataYaml(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  for (const [label, pattern] of patternsToUse) {
    const regexPattern = pattern.replace(/\\\\/g, '\\');
    const regex = new RegExp(regexPattern, "g");
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

/**
 * Detects sensitive content using the Gemini API.
 * @param {string} content - File content.
 * @param {string} type - File type: 'txt', 'csv', 'md', 'json', 'yaml', 'yml'.
 * @param {string} apiKey - Gemini API Key.
 * @param {string} [customPrompt] - Custom prompt with {type} and {content}.
 * @returns {Promise<string>} - Gemini response with the analysis.
 */
export async function detectSensitiveDataWithGemini(content, type, apiKey, customPrompt) {
  let prompt;
  if (customPrompt && typeof customPrompt === "string" && customPrompt.trim().length > 0) {
    prompt = customPrompt
      .replace(/\{type\}/g, type)
      .replace(/\{content\}/g, content);
  } else {
    prompt = `
Analyze the following content from a file of type "${type}" and ONLY respond if you detect sensitive data.
If you detect anything, respond using exactly this Markdown format:

detected:

*   **Data type:** \`example found\` (brief explanation if applicable)
*   **Other type:** \`another example\` (brief explanation if applicable)
*   **Other type:** \`another example\` (brief explanation if applicable)

Where "Data type" should be the actual type of sensitive data detected 
(for example: phone numbers like 612 34 56 78, credit card numbers like 4111 5441 3111 1111, email addresses like usuario.ejemplo@gmail.com, bank accounts like 2100 0418 4502 0005 1332) 
and "example found" should be a real example of the data found in the content.

**You must enumerate ALL different types of sensitive data you find in the content, each on a separate line.**

**Do not omit any type of sensitive data. If there are several, list them all, even if they are of the same type but with different values.**

If there is nothing sensitive, respond exactly: No sensitive content detected.

Content:
${content}
`;
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    })
  });

  if (!response.ok) {
    throw new Error("Error al consultar la API de Gemini");
  }

  const data = await response.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || "Sin respuesta de Gemini";
}

