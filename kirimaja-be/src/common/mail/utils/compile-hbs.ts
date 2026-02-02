import * as fs from 'fs';
import * as path from 'path';
import * as Handlebars from 'handlebars';

const cache = new Map<string, Handlebars.TemplateDelegate>();

export function compileHbs(
  templateName: string,
  data: Record<string, any>,
): string {
  if (!cache.has(templateName)) {
    const templatePath = path.join(
      process.cwd(),
      'src',
      'mail',
      'templates',
      `${templateName}.hbs`,
    );

    const source = fs.readFileSync(templatePath, 'utf-8');
    cache.set(templateName, Handlebars.compile(source));
  }

  return cache.get(templateName)!(data);
}
