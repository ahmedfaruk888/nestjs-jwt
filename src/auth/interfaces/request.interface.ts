import { Request } from 'express';

export interface ReqToken extends Request {
  user: {
    sub: number;
    email: string;
    refreshToken: string;
  };
}
