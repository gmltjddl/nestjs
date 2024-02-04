import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User } from 'src/domain/user.entity';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRole = this.reflector.get<string>('role', context.getHandler());
    console.log('Required Role:', requiredRole);
    if (!requiredRole) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user: User = request.user;
    console.log('User:', user);
    console.log('User Role:', user?.role);
    return user && user.role === requiredRole;
}
 
}