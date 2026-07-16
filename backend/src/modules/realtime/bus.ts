/**
 * Bus de eventos en tiempo real: guarda la referencia a Socket.io (fijada en
 * index.ts al crear el servidor) para que cualquier modulo pueda emitir sin
 * tener que recibir `io` por parametro. Emision best-effort: si aun no hay io,
 * simplemente no emite (no lanza).
 */
import type { Server as SocketServer } from 'socket.io';

let ioRef: SocketServer | null = null;

export function setIo(io: SocketServer): void {
  ioRef = io;
}

export function emitToAll(event: string, payload: unknown): void {
  ioRef?.emit(event, payload);
}
