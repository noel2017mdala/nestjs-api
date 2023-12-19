import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './DTO';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { LoginDTO } from './DTO/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
// import { User, Bookmark } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async login(params: LoginDTO) {
    const user = await this.prisma.user.findUnique({
      where: { email: params.email },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials provided');
    }
    const verifyPassword = await bcrypt.compare(params.password, user.hash);

    if (!verifyPassword) {
      throw new ForbiddenException('Invalid credentials provided');
    }

    return this.signToken(user.id, user.email);
  }

  async signUp(params: AuthDTO) {
    try {
      const hashedPassword = await bcrypt.hash(params.password, 12);

      const user = await this.prisma.user.create({
        data: {
          email: params.email,
          hash: hashedPassword,
          firstName: params.firstName,
          lastName: params.lastName,
        },
      });

      if (user) {
        return user;
      }

      return [];
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException();
        }
      }

      throw error;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{
    access_token: string;
  }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });

    return {
      access_token: token,
    };
  }
}
