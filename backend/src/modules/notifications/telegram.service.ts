/**
 * Envio de mensajes por Telegram usando la Bot API (HTTP, sin polling).
 * Solo se usa para enviar; no requiere la libreria pesada con long-polling.
 */
import axios from 'axios';
import { env } from '../../config/env';

export function isTelegramConfigured(): boolean {
  return Boolean(env.TELEGRAM_BOT_TOKEN);
}

const apiUrl = () => `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}`;

/** Envia un mensaje (Markdown) a uno o varios chats. */
export async function sendTelegram(chatIds: string[], text: string): Promise<void> {
  if (!isTelegramConfigured()) {
    throw new Error('Telegram no configurado (define TELEGRAM_BOT_TOKEN en el .env)');
  }
  for (const chatId of chatIds) {
    await axios.post(`${apiUrl()}/sendMessage`, {
      chat_id: chatId,
      text,
      parse_mode: 'Markdown',
      disable_web_page_preview: true,
    });
  }
}

/** Verifica el token del bot (getMe) para el boton de prueba. */
export async function verifyTelegram(): Promise<{ username: string }> {
  if (!isTelegramConfigured()) throw new Error('Telegram no configurado');
  const { data } = await axios.get<{ ok: boolean; result: { username: string } }>(
    `${apiUrl()}/getMe`
  );
  return { username: data.result.username };
}
