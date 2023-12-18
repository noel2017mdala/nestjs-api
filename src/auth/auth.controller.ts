import { Body, Controller, Post, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDTO } from './DTO';
import { LoginDTO } from './DTO/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  signUp(
    @Body(
      new ValidationPipe({
        whitelist: true,
      }),
    )
    dto: AuthDTO,
  ) {
    return this.authService.signUp(dto);
  }

  @Post('/login')
  login(@Body(ValidationPipe) dto: LoginDTO) {
    return this.authService.login(dto);
  }
}
