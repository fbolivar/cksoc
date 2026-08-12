/**
 * Cliente Socket.io para metricas en vivo.
 * Se conecta al mismo origen (Nginx hace proxy de /socket.io al backend).
 */
import { io, type Socket } from 'socket.io-client';
import { tokenStorage } from './api';

export interface LiveMetrics {
  total: number;
  byBand: { baja: number; media: number; alta: number; critica: number };
  updatedAt: string;
}

let socket: Socket | null = null;

export function getSocket(): Socket {
  if (!socket) {
    socket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnectionDelay: 2000,
      // Envia la cookie de sesion (HttpOnly) en el handshake same-origin.
      withCredentials: true,
      // Compatibilidad: si aun existe un token legado en localStorage, viaja
      // tambien en el handshake. Como funcion, se re-evalua en cada (re)conexion.
      auth: (cb) => cb({ token: tokenStorage.get() ?? '' }),
    });
  }
  return socket;
}
