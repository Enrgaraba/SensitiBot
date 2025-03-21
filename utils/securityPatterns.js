import Papa from "papaparse";

export const patterns = {
    'Phone number': /\b\d{3} \d{2} \d{2} \d{2}\b/,
    'Credit card number': /\b(?:\d[ -]*?){13,16}\b/,
    'Email address': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/
  };

  export function detectSensitiveDataTxt(file, content, context) {
    const detectedIssues = [];
    for (const [issue, regex] of Object.entries(patterns)) {
      if (regex.test(content)) {
        context.log.warn(`${issue} found in ${file}`);
        detectedIssues.push(issue);
      }
    }
    return detectedIssues;
  }
  
  export function detectSensitiveDataCsv(file, content, context) {
    const detectedIssues = [];
    
    // Parsear el contenido CSV
    const { data } = Papa.parse(content, { header: false, skipEmptyLines: true });
  
    // Recorrer las filas y buscar datos sensibles
    for (const row of data) {
      for (const [issue, regex] of Object.entries(patterns)) {
        if (row.some(cell => regex.test(cell))) {
          context.log.warn(`${issue} found in ${file}`);
          detectedIssues.push(issue);
          break;
        }
      }
    }
    return detectedIssues;
  }