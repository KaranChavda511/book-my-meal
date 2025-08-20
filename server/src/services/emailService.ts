import nodemailer from 'nodemailer';

const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT );
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASSWORD;
const fromEmail = process.env.FROM_EMAIL ;

if (!host || !user || !pass) {
  console.warn('[emailService] SMTP env vars missing. Emails will fail unless configured.');
}

const transporter = nodemailer.createTransport({
  host,
  port,
  secure: port === 465, // true for 465, false for 587/25
  auth: { user, pass }
});

export const sendMail = async (to: string, subject: string, html: string) => {
  return transporter.sendMail({
    from: fromEmail,
    to,
    subject,
    html
  });
};

export const sendPasswordResetEmail = async (to: string, resetLink: string) => {
  const subject = 'Reset your password';
  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.6;">
      <h2>Reset your password</h2>
      <p>We received a request to reset your password. Click the button below to set a new password.</p>
      <p>
        <a href="${resetLink}" style="display:inline-block;padding:10px 16px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;">Reset Password</a>
      </p>
      <p>Or open this link: <br/><a href="${resetLink}">${resetLink}</a></p>
      <p>If you did not request this, you can ignore this email.</p>
    </div>
  `;
  return sendMail(to, subject, html);
};

