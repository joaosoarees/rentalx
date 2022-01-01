import { NextFunction, Request } from 'express';
import { verify } from 'jsonwebtoken';

import { AppError } from '../errors/AppError';
import { UsersRepository } from '../modules/accounts/repositories/implementations/UsersRepository';

interface IVerifyPayload {
  sub: string;
}

export async function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
): Promise<void> {
  const { authorization } = request.headers;

  if (!authorization) {
    throw new AppError('Token missing.', 401);
  }

  const [, token] = authorization.split(' ');

  try {
    const { sub: userId } = verify(
      token,
      '0401a3df4c1f3455c6bd1edd460a383d'
    ) as IVerifyPayload;

    const usersRepository = new UsersRepository();

    const user = await usersRepository.findById(userId);

    if (!user) {
      throw new AppError('User does not exists', 401);
    }

    next();
  } catch {
    throw new AppError('Invalid token', 401);
  }
}
