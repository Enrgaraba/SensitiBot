export async function fetchFileContent(context, payload, file) {
  try {
    const content = await context.octokit.repos.getContent({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      path: file,
      ref: payload.ref
    });

    return Buffer.from(content.data.content, 'base64').toString('utf-8');
  } catch (error) {
    context.log.error(`Error fetching content for ${file}:`, error);
    return null;
  }
}

export const parseConfiguration = (configContent) => {
  const config = {};

  // Extract patterns from lines like PatternX: ['Label': /regex/]
  const patterns = [];
  const patternLineRegex = /Pattern\d+:\s*\[\s*'([^']+)':\s*\/(.+)\/\s*\]/g;
  let match;
  while ((match = patternLineRegex.exec(configContent)) !== null) {
    const label = match[1];
    const pattern = match[2];
    patterns.push([label, pattern]); 
  }
  config.patterns = patterns;

  // Extract file types
  const allowedFileTypes = ['txt', 'csv', 'md', 'json', 'yaml', 'yml'];
  const fileTypesMatch = configContent.match(/FileTypes:\s*\[(.*?)\]/s);
  if (fileTypesMatch) {
    config.fileTypes = fileTypesMatch[1]
      .split(',')
      .map(ext => ext.replace(/['"\s]/g, ''))
      .filter(ext => allowedFileTypes.includes(ext));
    // If there are no valid types, use the default ones
    if (config.fileTypes.length === 0) config.fileTypes = ['txt', 'csv', 'md', 'json', 'yaml', 'yml'];
  } else {
    config.fileTypes = ['txt', 'csv', 'md', 'json', 'yaml', 'yml'];
  }

  // Extract onDetection action
  const onDetectionMatch = configContent.match(/OnDetection:\s*(\w+)/);
  const allowedOnDetection = ["Block", "Full", "Alert"];
  if (onDetectionMatch && allowedOnDetection.includes(onDetectionMatch[1])) {
    config.onDetection = onDetectionMatch[1];
  } else {
    config.onDetection = "Alert";
  }

  // Extract exclusions
  const exclusionsMatch = configContent.match(/Exclusions:\s*\[(.*?)\]/s);
  if (exclusionsMatch) {
    config.exclusions = exclusionsMatch[1]
      .split(',')
      .map(item => {
        const trimmed = item.trim();
        return trimmed.replace(/^['"]|['"]$/g, '');
      })
      .filter(Boolean);
  } else {
    config.exclusions = [];
  }

  // Extract detection engine (patterns, gemini, ambos)
  const detectionEngineMatch = configContent.match(/DetectionEngine:\s*(\w+)/i);
  const allowedEngines = ['patterns', 'gemini'];
  if (detectionEngineMatch && allowedEngines.includes(detectionEngineMatch[1].toLowerCase())) {
    config.detectionEngine = detectionEngineMatch[1].toLowerCase();
  } else {
    config.detectionEngine = "patterns";
  }

  // Extract Gemini custom prompt (must be inside [])
  const geminiPromptMatch = configContent.match(/GeminiPrompt:\s*\[(.*?)\]/s);
  if (geminiPromptMatch && geminiPromptMatch[1].trim().length > 0) {
    config.geminiPrompt = geminiPromptMatch[1].trim();
  } else {
    config.geminiPrompt = null;
  }

  return config;
};