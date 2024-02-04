import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/domain/user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'yourSecretKey', // 여기에는 JWT 비밀키를 설정해야 합니다.
    });
  }

  async validate(payload: any): Promise<any> {
    // 'sub'는 JWT 토큰의 subject를 나타내며, 여기서는 사용자 ID를 의미합니다.
    const user = await this.userRepository.findOne({ where: { id: payload.sub } });
    return user;
  }
}