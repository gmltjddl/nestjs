import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/domain/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from 'src/auth/jwt.strategy';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    PassportModule,
    TypeOrmModule.forFeature([User]),
    
    JwtModule.register({
      secret: 'yourSecretKey', // 실제 애플리케이션에서는 안전하게 관리해야 하는 비밀 키
      signOptions: { expiresIn: '60s' }, // 토큰 유효 시간 설정
    }),
  ],
  controllers: [UsersController],
  providers: [JwtStrategy,UsersService],
})
export class UsersModule {}
