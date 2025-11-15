import { z } from 'zod';

const createUserAddressSchema = z.object({
    address: z
        .string({
            required_error: 'Address is required',
            invalid_type_error: 'Address must be a string',
        })
        .min(1, {
            message: 'Address must be at least 1 character long',
        }),
    tag: z
        .string({
            required_error: 'Tag is required',
            invalid_type_error: 'Tag must be a string',
        })
        .min(1, {
            message: 'Tag must be at least 1 character long',
        }),
    label: z
        .string({
            required_error: 'Label is required',
            invalid_type_error: 'Label must be a string',
        })
        .min(1, {
            message: 'Label must be at least 1 character long',
        }),
    photo: z.string().optional().nullable(),
});

export class CreateUserAddressDto {
    static schema: z.ZodObject<any> = createUserAddressSchema;

    constructor(
        public address: string,
        public tag: string,
        public label: string,
        public photo?: string | null,
    ) {}
}
