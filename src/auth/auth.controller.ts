import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  public login(@Body() loginDto: AuthDto): Promise<{ access_token: string }> {
    return this.authService.login(loginDto);
  }

  @Post('register')
  public register(
    @Body() registerDto: AuthDto,
  ): Promise<{ access_token: string }> {
    return this.authService.register(registerDto);
  }
}
