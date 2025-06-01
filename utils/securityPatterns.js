import Papa from "papaparse";

// Default patterns to use if none are provided in the configuration
export const defaultPatterns = [
  ['Phone number', '\\b\\d{3} \\d{2} \\d{2} \\d{2}\\b'],
  ['Credit card number', '\\b(?:\\d[ -]*?){13,16}\\b'],
  ['Email address', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b']
];

/**
 * Detecta datos sensibles en cualquier tipo de archivo soportado por el bot.
 * El parámetro "type" debe ser uno de: 'txt', 'csv', 'md', 'json', 'yaml', 'yml'
 * El parámetro "fileTypes" es un array de extensiones soportadas, extraído del archivo de configuración.
 */
export function detectSensitiveDataForPR(file, content, context, patterns, exclusions, type, fileTypes) {


  // Extrae la extensión real del archivo
  const fileExt = '.' + file.split('.').pop().toLowerCase();
  if (!fileTypes.includes(fileExt)) {
    context.log.info(`File extension "${fileExt}" for file "${file}" is not enabled in configuration. Skipping.`);
    return [];
  }

  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detectedMatches = [];

  // Utilidad para filtrar exclusiones
  const filterExclusions = (matches) =>
    exclusions && exclusions.length > 0
      ? matches.filter(match => !exclusions.includes(match))
      : matches;

  // Selección de lógica según tipo de archivo
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
  } else {
    // txt, md y cualquier otro: texto plano
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

export function detectSensitiveDataTxt(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  for (const [label, pattern] of patternsToUse) {
    // Desescapa las barras dobles a simples
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

export function detectSensitiveDataJson(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  let jsonObj;
  try {
    jsonObj = JSON.parse(content);
  } catch (e) {
    return detected; // Si no es JSON válido, no detecta nada
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

export function detectSensitiveDataYaml(content, patterns, exclusions) {
  const patternsToUse = (patterns && patterns.length > 0) ? patterns : defaultPatterns;
  const detected = [];
  // No se parsea YAML, se busca sobre el texto plano
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

