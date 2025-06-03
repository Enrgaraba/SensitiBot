import Papa from "papaparse";
// Importa los patrones desde patterns.js
import { defaultPatterns } from "./patterns.js";

/**
 * Detecta datos sensibles en cualquier tipo de archivo soportado por el bot.
 * El parámetro "type" debe ser uno de: 'txt', 'csv', 'md', 'json', 'yaml', 'yml'
 * El parámetro "fileTypes" es un array de extensiones soportadas, extraído del archivo de configuración.
 */
export function detectSensitiveDataForPR(file, content, context, patterns, exclusions, type, fileTypes) {

  // Extrae la extensión real del archivo
  const fileExt =  file.split('.').pop().toLowerCase();
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

/**
 * Detecta contenido sensible usando la API de Gemini.
 * @param {string} content - Contenido del archivo.
 * @param {string} type - Tipo de archivo: 'txt', 'csv', 'md', 'json', 'yaml', 'yml'.
 * @param {string} apiKey - API Key de Gemini.
 * @param {string} [customPrompt] - Prompt personalizado con {type} y {content}.
 * @returns {Promise<string>} - Respuesta de Gemini con el análisis.
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

