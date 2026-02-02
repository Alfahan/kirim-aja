import { Injectable, Logger } from '@nestjs/common';
import { mailTransporter } from './mail.config';
import { compileHbs } from './utils/compile-hbs';

interface SendMailParams {
  to: string;
  subject: string;
  html?: string;
  template?: {
    name: string;
    context: Record<string, any>;
  };
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  async send(params: SendMailParams) {
    const html = params.html ?? this.compileTemplate(params.template);

    const info = await mailTransporter.sendMail({
      from: process.env.MAIL_FROM,
      to: params.to,
      subject: params.subject,
      html,
    });

    this.logger.log(`Email sent to ${params.to}`);
    return info;
  }

  private compileTemplate(
    template?: SendMailParams['template'],
  ): string {
    if (!template) {
      throw new Error('Either html or template must be provided');
    }

    return compileHbs(template.name, template.context);
  }
}

// cara pakai
// await mailService.send({
//   to: 'user@mail.com',
//   subject: 'Verify Email',
//   template: {
//     name: 'verify-email',
//     context: {
//       name: 'Budi',
//       link: 'http://localhost:3000/verify?token=xxx',
//       expiresIn: 15,
//     },
//   },
// });

