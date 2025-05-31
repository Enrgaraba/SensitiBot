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

  // Extraer patrones de líneas tipo PatternX: ['Label': /regex/]
  const patterns = [];
  const patternLineRegex = /Pattern\d+:\s*\[\s*'([^']+)':\s*\/(.+)\/\s*\]/g;
  let match;
  while ((match = patternLineRegex.exec(configContent)) !== null) {
    const label = match[1];
    const pattern = match[2];
    patterns.push([label, pattern]); // <-- Cambiado a formato [label, pattern]
  }
  config.patterns = patterns;

  // Extract file types
  const fileTypesMatch = configContent.match(/FileTypes:\s*\[(.*?)\]/s);
  if (fileTypesMatch) {
    config.fileTypes = fileTypesMatch[1]
      .split(',')
      .map(ext => ext.replace(/['"\s]/g, ''))
      .filter(Boolean);
  } else {
    config.fileTypes = [];
  }

  // Extract onDetection action
  const onDetectionMatch = configContent.match(/OnDetection:\s*(\w+)/);
  config.onDetection = onDetectionMatch ? onDetectionMatch[1] : "Alert";

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

  return config;
};