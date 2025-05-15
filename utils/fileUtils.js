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
  
    // Extract patterns
    const patternsMatch = configContent.match(/PatternsList:\s*\[(.*?)\]/s);
    config.patterns = patternsMatch ? eval(`[${patternsMatch[1]}]`) : [];
  
    // Extract file types
    const fileTypesMatch = configContent.match(/FileTypes:\s*\[(.*?)\]/s);
    config.fileTypes = fileTypesMatch ? eval(`[${fileTypesMatch[1]}]`) : [];
  
    // Extract onDetection action
    const onDetectionMatch = configContent.match(/OnDetection:\s*(\w+)/);
    config.onDetection = onDetectionMatch ? onDetectionMatch[1] : "Alert";
  
    // Extract exclusions
    const exclusionsMatch = configContent.match(/Exclusions:\s*\[(.*?)\]/s);
    config.exclusions = exclusionsMatch ? eval(`[${exclusionsMatch[1]}]`) : [];
  
    return config;
  };