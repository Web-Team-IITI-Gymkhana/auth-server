import { IsNotEmpty, IsString, IsEmail, Length, IsBoolean, IsEnum, IsOptional } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(3, 20, { message: 'Passowrd has to be at between 3 and 20 chars' })
  public password: string;

  @IsString()
  @IsOptional()
  public hashedRT: string;

  @IsString()
  @IsOptional()
  public authType: string;

  @IsBoolean()
  @IsOptional()
  public isVerified: boolean;
}
