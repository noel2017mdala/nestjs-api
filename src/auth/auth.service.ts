import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './DTO';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { LoginDTO } from './DTO/login.dto';
// import { User, Bookmark } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
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

    delete user.hash;

    return user;
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
}
