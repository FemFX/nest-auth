import { Provider, Role, User } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserResponse implements User {
    id: string;
    email: string;
    @Exclude()
    password: string;
    @Exclude()
    createdAt: Date;
    updatedAt: Date;
    roles: Role[];
    @Exclude()
    provider: Provider;
    constructor(user: User) {
        Object.assign(this, user);
    }
}
