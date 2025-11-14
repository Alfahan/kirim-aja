import { z, ZodObject } from 'zod';

const createBranchSchema = z.object({
    name: z
        .string({
            required_error: 'Branch name is required',
            invalid_type_error: 'Branch name must be a string',
        })
        .min(1, {
            message: 'Branch name must be at least 1 character long',
        }),
    address: z
        .string({
            required_error: 'Branch address is required',
            invalid_type_error: 'Branch address must be a string',
        })
        .min(1, {
            message: 'Branch address must be at least 1 character long',
        }),
    phone_number: z
        .string({
            required_error: 'Branch phone number is required',
            invalid_type_error: 'Branch phone number must be a string',
        })
        .min(1, {
            message: 'Branch phone number must be at least 1 character long',
        }),
});

export class CreateBranchDto {
    static schema: ZodObject<any> = createBranchSchema;

    constructor(
        public readonly name: string,
        public readonly address: string,
        public readonly phone_number: string,
    ) {}
}
