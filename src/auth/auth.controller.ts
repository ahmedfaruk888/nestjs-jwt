import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { ReqToken } from './interfaces';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  sigupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.sigupLocal(dto);
  }
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  siginLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.siginLocal(dto);
  }
  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request) {
    const user = req.user;
    return this.authService.logout(user['sub']);
  }
  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@Req() req: ReqToken) {
    const { sub: userId, refreshToken } = req.user;
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
