### NestJs를 사용한 사용자 인증과 권한 관리시스템

#### + TypeScript와 mysql을 사용하여 백엔드 구현

#### + 사용자 인증은 JWT 토큰을 사용하여 구현

<br>
프로젝트 제작 기간 : 2024 2/1 ~ 2/5
<br>
프로젝트 구성 인원 : 1명

프로젝트 기술 스택 : TypeScript, NestJs, MySQL, AWS SES, TypeORM, JWT, PostMan
<br><br>

## **목표:**

- 사용자의 회원가입, 로그인, 비밀번호 변경을 처리하는 API를 구현합니다.
- JWT를 사용하여 토큰 기반의 인증 시스템을 구축하고, 권한을 관리합니다.

## **요구사항:**

1. **회원가입 API**
    - (일반회원) 사용자는 이메일과 비밀번호로 회원가입
    - 이메일은 중복 X 
    - 비밀번호는 안전한 방식으로 저장

2. **로그인 API**
    - 이메일과 비밀번호로 로그인
    - 로그인 성공 시 JWT 토큰을 발급

3. **비밀번호 변경 API**
    - 로그인한 사용자는 비밀번호를 변경 가능
    - 새로운 비밀번호는 안전한 해싱 방식으로 저장

4. **회원 목록 조회 API**
    - 시스템에 등록된 회원 목록을 조회
    - 단, 관리자만 조회 가능
    
5. **이메일 인증 기능 API**
      - 회원가입시 AWS SES를 사용한 이메일 인증 기능 추가

6. **Refresh 토큰 재발급 API**
    - Refresh 토큰을 사용하여 토큰 재발급 추가
     
7. **로그인 시도 제한 기능**
    - 로그인 시도 제한 기능(최대 5회) 추가

8. **중복 로그인 방지 기능**
    - 중복 로그인 방지 기능 추가