import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { User } from "src/domain/user.entity";
import { Repository } from "typeorm";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService, private userRepository: Repository<User>) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.split(' ')[1]; // Bearer 토큰에서 JWT 추출

    if (!token) {
      throw new UnauthorizedException('토큰이 제공되지 않았습니다.');
    }

    const decoded = this.jwtService.decode(token);
    if (!decoded) {
      throw new UnauthorizedException('유효하지 않은 토큰입니다.');
    }

    const user = await this.userRepository.findOne(decoded.sub);
    if (!user || user.currentToken !== token) {
      throw new UnauthorizedException('중복 로그인이 감지되었습니다.');
    }

    return true;
  }
}