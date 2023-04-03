// import { Body, Controller, Delete, Get, Inject, Param, Post } from '@nestjs/common';
import { Controller, Get, Inject, Param } from '@nestjs/common';

// import { User } from './user.entity';
import { CreateUserDto } from './user.dtos';
import { USER_SERVICE } from 'src/constants';
import { Req, UseGuards } from '@nestjs/common';

import { UserService } from './user.service';
import { log } from 'console';
import { AtGuard } from 'src/common/guards';

@Controller('users')
export class UserController {
  constructor(@Inject(USER_SERVICE) private readonly usersService: UserService) {}

  // @Post()
  // create(@Body() createUserDto: CreateUserDto): Promise<User> {
  //   return this.usersService.create(new User(createUserDto));
  // }

  // @Get()
  // findAll(): Promise<User[]> {
  //   return this.usersService.findAll();
  // }

  // @Get(':id')
  // findOne(@Param('id') id: string): Promise<User> {
  //   return this.usersService.findOne(id);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string): Promise<void> {
  //   return this.usersService.remove(id);
  // }

  @UseGuards(AtGuard)
  @Get('me/:id')
  getMyUser(@Param() params: { id: string }, @Req() req) {
    console.log(params.id);
    return this.usersService.getMyUser(params.id, req);
  }

  @Get()
  getUsers() {
    return this.usersService.getUsers();
  }
}
