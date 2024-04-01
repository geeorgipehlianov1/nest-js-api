import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  public async login({ email, password }: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
      select: {
        id: true,
        hash: true,
        email: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    const isPasswordMatch = await argon.verify(user.hash, password);

    if (!isPasswordMatch) {
      throw new ForbiddenException('Credentials incorrect');
    }

    return user;
  }

  public async register({ email, password }: AuthDto) {
    try {
      const hash = await argon.hash(password);

      const user = await this.prisma.user.create({
        data: {
          email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }
}
