import { z } from "zod";

const createShipmentSchema = z.object({
    pickup_address_id: z.
        number({
            required_error: 'Pickup address ID is required',
            invalid_type_error: 'Pickup address ID must be a number',
        })
        .int({
            message: 'Pickup address ID must be an integer'
        }),
    destination_address: z
        .string({
            required_error: 'Destination address is required',
            invalid_type_error: 'Destination address must be a string',
        })
        .min(1, {
            message: 'Destination address must be at least 1 character long',
        }),
    recipient_name: z
        .string({
            required_error: 'Recipient name is required',
            invalid_type_error: 'Recipient name must be a string'
        })
        .min(1, {
            message: 'Recipient name must be at least 1 character long',
        }),
    recipient_phone: z
        .string({
            required_error: 'Recipient phone is required',
            invalid_type_error: 'Recipient phone must be a string'
        })
        .min(10, {
            message: 'Recipient name must be at least 10 character long',
        }),
    weight: z.
        number({
            required_error: 'Weight is required',
            invalid_type_error: 'Weight must be a number'
        })
        .positive({
            message: 'Weight must be a positive number'
        }),
    package_type: z
        .string({
            required_error: 'Package type is required',
            invalid_type_error: 'Package type must be a string'
        })
        .min(1, {
            message: 'Package type must be at least 1 character long',
        }),
    delivery_type: z
        .string({
            required_error: 'Delivery type is required',
            invalid_type_error: 'Delivery type must be a string'
        })
        .min(1, {
            message: 'Delivery type must be at least 1 character long',
        })
})

export class CreateShipmentDto {
    static schema: z.ZodObject<any> = createShipmentSchema;

    constructor(
        public pickup_address_id: number,
        public destination_address: string,
        public recipient_name: string,
        public recipient_phone: string,
        public weight: number,
        public package_type: string,
        public delivery_type: string,
    ) {}
}
