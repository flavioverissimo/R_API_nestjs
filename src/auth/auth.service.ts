/* eslint-disable prettier/prettier */
import { Injectable, ForbiddenException } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from '@nestjs/jwt';


@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(dto: AuthDto){
    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data:{
          email: dto.email,
          hash,
        },
      })

      return this.signToken(user.email, user.id);

    } catch(error) {
      if (error instanceof PrismaClientKnownRequestError && error.code === "P2002") {
        throw new ForbiddenException("Credentials Taken")
      }
      throw error;
    }
  }

  async signin(dto: AuthDto){
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    })
    if (!user) throw new ForbiddenException("Email or password invalid.")

    const passwordMatches = await argon.verify(user.hash, dto.password)
    if (!passwordMatches) throw new ForbiddenException("Email or password invalid.")

    return this.signToken(user.email, user.id);
  }

  async signToken(email: string, userId: number) {
    const payload = { sub: userId, email}
    const token = await this.jwtService.signAsync(payload, {expiresIn: "60m"})

    return {
      access_token: token
    }
  }
}
