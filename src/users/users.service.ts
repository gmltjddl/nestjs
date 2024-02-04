import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from 'src/domain/user.entity';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { ChangePasswordDto } from './dto/change-password.dto';
import * as AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';


@Injectable()
export class UsersService {
  private ses: AWS.SES;

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService 
  ){
    AWS.config.update({
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      region: process.env.AWS_REGION
    });

    this.ses = new AWS.SES({ apiVersion: '2010-12-01' });
  }


  async create(createUserDto: CreateUserDto) {
    // 이메일 중복 확인
    const existingUser = await this.userRepository.findOne({ 
      where: { email: createUserDto.email } 
    });

    if (existingUser) {
      throw new Error('이미 사용 중인 이메일입니다.');
    }

    // 중복되지 않은 경우, 회원가입 로직 진행
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const emailVerificationToken = uuidv4();
    const user = new User();
    user.email = createUserDto.email;
    user.password = hashedPassword;
    user.role = UserRole.MEMBER; // 기본적으로 사용자 역할을 'MEMBER'로 설정
    user.emailVerificationToken = emailVerificationToken;

    await this.userRepository.save(user);
    await this.sendVerificationEmail(user.email, emailVerificationToken);


    return { message: '회원가입에 성공했습니다. 이메일을 확인해주세요' }; 
  }

  private async sendVerificationEmail(email: string, verificationToken: string) {
    const params = {
      Source: 'gmltjd7886@gmail.com',
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: '이메일 인증' },
        Body: {
          Html: {
            Data: `인증 토큰: ${verificationToken}, <a href="${process.env.FRONTEND_URL}?token=${verificationToken}">여기를 클릭하여 인증하세요</a>`
          }
        }
      }
    };

    await this.ses.sendEmail(params).promise();
  }

  async verifyEmail(token: string) {
    const user = await this.userRepository.findOne({ 
      where: { emailVerificationToken: token } 
    });
  
    if (!user) {
      throw new Error('잘못된 인증 토큰입니다.');
    }
  
    user.emailVerified = true;
    user.emailVerificationToken = null; // 토큰 초기화
    console.log(user.emailVerificationToken);
    await this.userRepository.save(user); // 변경사항 저장
  
    return { message: '이메일 인증이 완료되었습니다.' };
  }

  async login(loginUserDto: LoginUserDto) {
    const user = await this.userRepository.findOne({ where: { email: loginUserDto.email } });

    // 계정이 잠겼는지 확인
    if (user && user.isLocked) {
      throw new Error('계정이 잠겼습니다. 잠시 후 다시 시도해 주세요.');
    }

    if (user && await bcrypt.compare(loginUserDto.password, user.password)) {
      // JWT 토큰 생성
      const accessTokenPayload = { sub: user.id, role: user.role };
      const accessToken = this.jwtService.sign(accessTokenPayload);

      // 중복 로그인 방지를 위해 currentToken 업데이트
      user.currentToken = accessToken;
      await this.userRepository.save(user);

      // JWT refresh token 생성
      const refreshTokenPayload = { sub: user.id, tokenType: 'refresh' };
      const refreshToken = this.jwtService.sign(refreshTokenPayload, { expiresIn: '7d' });

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
        message: "로그인에 성공했습니다."
      };
    } else {
      if (user) {
        // 로그인 실패: 실패 횟수 증가
        user.loginAttempts += 1;
        if (user.loginAttempts >= 5) {
          // 5회 이상 실패 시 계정 잠금
          user.isLocked = true;
        }
        await this.userRepository.save(user);
      }
      throw new Error('이메일 또는 비밀번호가 다릅니다!');
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken);
      if (payload.tokenType !== 'refresh') {
        throw new Error('Invalid token type');
      }

      const newAccessTokenPayload = { sub: payload.sub };
      const newAccessToken = this.jwtService.sign(newAccessTokenPayload);

      return {
        access_token: newAccessToken
      };
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }
  }
  
  async findAll() {
    return await this.userRepository.find();
  }
  
  async findOne(id: number) {
    return await this.userRepository.findOne({where: {id}});
  }
  
  async update(id: number, updateUserDto: UpdateUserDto) {
    const user = await this.findOne(id);
    if(!user){
      throw new Error('user not found');
    }
    Object.assign(user, updateUserDto);
    return await this.userRepository.save(user);
  }
  
  async remove(id: number) {
    const user = await this.findOne(id);
    if(!user){
      throw new Error('user not found');
    }
    return await this.userRepository.remove(user);
  }

 async changePassword(userId: number, changePasswordDto: ChangePasswordDto) {
  // findOne 메소드에 객체 형태로 조건을 전달합니다.
  const user = await this.userRepository.findOne({ where: { id: userId } });

  if (!user) {
    throw new Error('사용자를 찾을 수 없습니다.');
  }

  const isMatch = await bcrypt.compare(changePasswordDto.oldPassword, user.password);
  if (!isMatch) {
    throw new Error('현재 비밀번호가 일치하지 않습니다.');
  }

  user.password = await bcrypt.hash(changePasswordDto.newPassword, 10);
  await this.userRepository.save(user);
}

}
