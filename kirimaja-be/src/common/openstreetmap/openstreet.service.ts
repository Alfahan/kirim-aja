import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';

@Injectable()
export class OpenStreetService {
    private readonly logger = new Logger(OpenStreetService.name);
    private readonly nominatimUrl =
        process.env.NOMINATIM_URL ||
        'https://nominatim.openstreetmap.org/search';

    async geocode(
        address: string,
    ): Promise<{ lat: number; lng: number; displayName?: string } | null> {
        if (!address?.trim()) {
            throw new HttpException(
                'Address is required and cannot be empty',
                HttpStatus.BAD_REQUEST,
            );
        }

        const trimmedAddress = address.trim();

        if (trimmedAddress.length < 5) {
            throw new HttpException(
                'Address is too short. Please provide a more specific address',
                HttpStatus.BAD_REQUEST,
            );
        }

        try {
            this.logger.debug(`Geocoding address: ${trimmedAddress}`);

            const url = `${this.nominatimUrl}?q=${encodeURIComponent(trimmedAddress)}&format=json&limit=1&addressdetails=1`;

            const response = await fetch(url, {
                headers: {
                    'User-Agent': 'YourAppName/1.0 (your-email@domain.com)',
                    Accept: 'application/json',
                },
            });

            if (!response.ok) {
                this.logger.error(
                    `Geocoding API error: ${response.status} ${response.statusText}`,
                );
                throw new HttpException(
                    `Geocoding service temporarily unavailable. Please try again later.`,
                    HttpStatus.SERVICE_UNAVAILABLE,
                );
            }

            const data = await response.json();

            if (!Array.isArray(data) || data.length === 0) {
                this.logger.warn(
                    `No results found for address: ${trimmedAddress}`,
                );
                return null;
            }

            const result = data[0];

            if (!result.lat || !result.lon) {
                this.logger.warn(
                    `Invalid coordinates in response for address: ${trimmedAddress}`,
                );
                return null;
            }

            const lat = parseFloat(result.lat);
            const lng = parseFloat(result.lon);

            if (
                isNaN(lat) ||
                isNaN(lng) ||
                lat < -90 ||
                lat > 90 ||
                lng < -180 ||
                lng > 180
            ) {
                this.logger.warn(
                    `Invalid coordinate values for address: ${trimmedAddress}`,
                );
                return null;
            }

            this.logger.debug(
                `Successfully geocoded address: ${trimmedAddress} -> ${lat}, ${lng}`,
            );

            return {
                lat,
                lng,
            };
        } catch (error) {
            if (error instanceof HttpException) {
                throw error;
            }

            this.logger.error(
                `Geocoding failed for address: ${trimmedAddress}`,
                error.stack,
            );

            throw new HttpException(
                'Geocoding service is temporarily unavailable. Please try again later.',
                HttpStatus.SERVICE_UNAVAILABLE,
            );
        }
    }

    // Fixed batch geocoding
    async geocodeBatch(
        addresses: string[],
        delayMs: number = 1000,
    ): Promise<
        Array<{ lat: number; lng: number; displayName?: string } | null>
    > {
        const results: Array<{
            lat: number;
            lng: number;
            displayName?: string;
        } | null> = [];

        for (const address of addresses) {
            try {
                const result = await this.geocode(address);
                results.push(result);

                if (delayMs > 0) {
                    await this.delay(delayMs);
                }
            } catch (error) {
                this.logger.error(
                    `Batch geocoding failed for address: ${address}`,
                    error,
                );
                results.push(null);
            }
        }

        return results;
    }

    async reverseGeocode(lat: number, lng: number): Promise<string | null> {
        try {
            const url = `${this.nominatimUrl.replace('/search', '/reverse')}?lat=${lat}&lon=${lng}&format=json`;

            const response = await fetch(url, {
                headers: {
                    'User-Agent': 'YourAppName/1.0 (your-email@domain.com)',
                    Accept: 'application/json',
                },
            });

            if (!response.ok) return null;

            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const data = await response.json();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
            return data.display_name || null;
        } catch (error) {
            this.logger.error('Reverse geocoding failed', error);
            return null;
        }
    }

    private delay(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
