import { z, ZodObject } from 'zod';

const employeeBranchSchema = z.object({
    name: z
        .string({
            required_error: 'Name is required',
            invalid_type_error: 'Name must be a string',
        })
        .min(1, {
            message: 'Name must be at least 1 character long',
        }),
    email: z
        .string({
            required_error: 'Email is required',
            invalid_type_error: 'Email must be a string',
        })
        .email({
            message: 'Email must be a valid email address',
        }),
    phone_number: z
        .string({
            required_error: 'Phone number is required',
            invalid_type_error: 'Phone number must be a string',
        })
        .min(10, {
            message: 'Phone number must be at least 10 character long',
        }),
    branch_id: z
        .number({
            required_error: 'Branch ID is required',
            invalid_type_error: 'Branch ID must be a string',
        })
        .int({
            message: 'Branch ID must be an integer',
        }),
    type: z
        .string({
            required_error: 'Type is required',
            invalid_type_error: 'Type must be a string',
        })
        .min(1, {
            message: 'Type mus be at least 1 character long',
        }),
    role_id: z
        .number({
            required_error: 'Role ID is required',
            invalid_type_error: 'Role ID must be a number',
        })
        .int({
            message: 'Role ID must be an integer',
        }),
    password: z
        .string({
            required_error: 'Password is required',
            invalid_type_error: 'Password must be a string',
        })
        .min(8, {
            message: 'Password must be at least 6 character long',
        }),
    avatar: z.string().optional().nullable(),
});

export class CreateEmployeeBranchDto {
    static schema: ZodObject<any> = employeeBranchSchema;

    constructor(
        public name: string,
        public email: string,
        public phone_number: string,
        public branch_id: number,
        public type: string,
        public role_id: number,
        public password: string,
        public avatar?: string | null,
    ) {}
}
