import { Injectable, HttpException, HttpStatus } from '@nestjs/common';

@Injectable()
export class GeocodingService {
    private readonly nominatimUrl = process.env.NOMINATIM_URL || 'https://nominatim.openstreetmap.org/search';

    async geocode(address: string): Promise<{ lat: number; lng: number; address: string } | null> {
        if (!address || address.trim().length === 0) {
            throw new HttpException('Address is required', HttpStatus.BAD_REQUEST);
        }

        try {
            const response = await fetch(
                `${this.nominatimUrl}?q=${encodeURIComponent(address)}&format=json&limit=1`,
            );

            if (!response.ok) {
                throw new HttpException(
                    `Geocoding service error: ${response.statusText}`,
                    HttpStatus.SERVICE_UNAVAILABLE
                );
            }

            const data = await response.json();
            
            if (data && data.length > 0) {
                return {
                    lat: parseFloat(data[0].lat),
                    lng: parseFloat(data[0].lon),
                    address: data[0].display_name,
                };
            }
            
            return null;
            
        } catch (error) {
            if (error instanceof HttpException) {
                throw error;
            }
            
            throw new HttpException(
                'Geocoding service unavailable',
                HttpStatus.SERVICE_UNAVAILABLE
            );
        }
    }
}