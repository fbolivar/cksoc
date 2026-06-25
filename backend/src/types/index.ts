/** Tipos compartidos del backend. */

export type RoleName = 'admin' | 'analista' | 'lector';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: RoleName;
}

/** Payload que viaja dentro del JWT. */
export interface JwtPayload {
  sub: string; // user id
  email: string;
  role: RoleName;
}

/** Extiende Express.Request para incluir el usuario autenticado. */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}
