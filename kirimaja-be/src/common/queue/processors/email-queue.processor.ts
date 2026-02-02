import { Process, Processor } from "@nestjs/bull";
import { Logger } from "@nestjs/common";
import { Job } from "bull";
import { MailService } from "src/common/mail/mail.service";

export interface EmailJobData {
    type: string;
    to: string;
}

@Processor('email-queue')
export class EmailQueueProcessor {
    private readonly logger = new Logger(EmailQueueProcessor.name);

    constructor(
        private readonly mailService: MailService,
    ) {}

    @Process('send-email')
    async handleSendEmail(job: Job<EmailJobData>) {
        const { data } = job;
        this.logger.log(`Processing email job: ${data.type} to ${data.to}`);

        try {
            switch (data.type) {
                case 'testing':
                    this.logger.log(`Test email send to ${data.to}`);
                    break;
                default:
                    this.logger.warn(`Unknown email type: ${data.to}`);
                    break;
            }
        } catch (e) {

        }
    }
}