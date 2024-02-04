import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";


export enum UserRole {
    ADMIN = "ADMIN",
    MEMBER = "MEMBER"
  }
  
@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    email: string;

    @Column()
    password: string;

    @Column({
        type: "enum",
        enum: UserRole,
        default: UserRole.MEMBER
      })
      role: UserRole;


      @Column({ nullable: true })
      emailVerificationToken: string;
    
      @Column({ default: false })
      emailVerified: boolean;

      @Column({ default: 0 })
      loginAttempts: number;
    
      @Column({ default: false })
      isLocked: boolean;

      @Column({ nullable: true })
      currentToken: string;
}