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
