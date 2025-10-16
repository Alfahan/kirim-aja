import {
    ConflictException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { AuthLoginDto } from './dto/auth-login.dto';
import {
    AuthLoginResponse,
    UserResponse,
} from './response/auth-login.response';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { plainToInstance } from 'class-transformer';
import { AuthRegisterDto } from './dto/auth-register.dto';

@Injectable()
export class AuthService {
    constructor(
        private prismaService: PrismaService,
        private jwtService: JwtService,
    ) {}

    async login(request: AuthLoginDto): Promise<AuthLoginResponse> {
        const user = await this.prismaService.user.findUnique({
            where: { email: request.email },
            include: {
                role: {
                    include: {
                        rolePermissions: {
                            include: {
                                permission: true,
                            },
                        },
                    },
                },
            },
        });

        if (!user) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const isPasswordValid = await bcrypt.compare(
            request.password,
            user?.password,
        );

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const payload = {
            sub: user.id,
            email: user?.email,
            name: user?.name,
            roleId: user?.roleId,
        };

        const accessToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_SECRET_KEY || 'secretKey',
            expiresIn: (process.env.JWT_EXPIRES_IN || '1h') as any,
        });

        const { password, ...userWithoutPassword } = user;

        const transformedUser = {
            ...userWithoutPassword,
            role: {
                ...user.role,
                permission: user.role.rolePermissions.map((rolePermission) => ({
                    id: rolePermission.permission.id,
                    name: rolePermission.permission.name,
                    key: rolePermission.permission.key,
                    resource: rolePermission.permission.resource,
                })),
            },
        };

        const userResponse = plainToInstance(UserResponse, transformedUser, {
            excludeExtraneousValues: true,
        });

        return plainToInstance(
            AuthLoginResponse,
            {
                accessToken,
                user: userResponse,
            },
            {
                excludeExtraneousValues: true,
            },
        );
    }

    async register(request: AuthRegisterDto): Promise<AuthLoginResponse> {
        const existingUser = await this.prismaService.user.findUnique({
            where: { email: request.email },
        });

        if (existingUser) {
            throw new ConflictException('Email already registered');
        }

        const role = await this.prismaService.role.findFirst({
            where: { key: 'customer' },
        });

        if (!role) {
            throw new NotFoundException('Role customer tidak ditemukan');
        }

        const hashedPassword = await bcrypt.hash(request.password, 10);

        const user = await this.prismaService.user.create({
            data: {
                name: request.name,
                email: request.email,
                password: hashedPassword,
                phoneNumber: request.phone_number,
                roleId: role.id,
            },
            include: {
                role: {
                    include: {
                        rolePermissions: {
                            include: {
                                permission: true,
                            },
                        },
                    },
                },
            },
        });

        const payload = {
            sub: user.id,
            email: user?.email,
            name: user?.name,
            roleId: user?.roleId,
        };

        const accessToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_SECRET_KEY || 'secretKey',
            expiresIn: (process.env.JWT_EXPIRES_IN || '1h') as any,
        });

        const { password, ...userWithoutPassword } = user;

        const transformedUser = {
            ...userWithoutPassword,
            role: {
                ...user.role,
                permission: user.role.rolePermissions.map(
                    (rolePermission: {
                        permission: {
                            id: any;
                            name: any;
                            key: any;
                            resource: any;
                        };
                    }) => ({
                        id: rolePermission.permission.id,
                        name: rolePermission.permission.name,
                        key: rolePermission.permission.key,
                        resource: rolePermission.permission.resource,
                    }),
                ),
            },
        };

        const userResponse = plainToInstance(UserResponse, transformedUser, {
            excludeExtraneousValues: true,
        });

        return plainToInstance(
            AuthLoginResponse,
            {
                accessToken,
                user: userResponse,
            },
            {
                excludeExtraneousValues: true,
            },
        );
    }
}
