/**
 * Envio de correos por SMTP (Nodemailer).
 * El transporte se crea perezosamente; si faltan credenciales SMTP,
 * isEmailConfigured() devuelve false y no se intenta enviar.
 */
import nodemailer, { type Transporter } from 'nodemailer';
import { env } from '../../config/env';

let transporter: Transporter | null = null;

export function isEmailConfigured(): boolean {
  return Boolean(env.SMTP_HOST && env.SMTP_PORT && env.SMTP_FROM);
}

function getTransporter(): Transporter {
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_SECURE,
    auth:
      env.SMTP_USER && env.SMTP_PASSWORD
        ? { user: env.SMTP_USER, pass: env.SMTP_PASSWORD }
        : undefined,
  });
  return transporter;
}

export interface MailAttachment {
  filename: string;
  content: Buffer;
  contentType?: string;
}

/** Envia un correo a uno o varios destinatarios (con adjuntos opcionales). */
export async function sendEmail(
  to: string[],
  subject: string,
  html: string,
  text: string,
  attachments?: MailAttachment[]
): Promise<void> {
  if (!isEmailConfigured()) {
    throw new Error('SMTP no configurado (define SMTP_HOST, SMTP_PORT y SMTP_FROM en el .env)');
  }
  await getTransporter().sendMail({
    from: env.SMTP_FROM,
    to: to.join(', '),
    subject,
    html,
    text,
    attachments,
  });
}

/** Verifica la conexion SMTP (para el boton de prueba). */
export async function verifyEmail(): Promise<void> {
  if (!isEmailConfigured()) throw new Error('SMTP no configurado');
  await getTransporter().verify();
}
