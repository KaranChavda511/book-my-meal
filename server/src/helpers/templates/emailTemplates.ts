export const buildResetLink = (token: string): string => {
  const base =
    process.env.RESET_PASSWORD_URL_BASE?.trim() ||
    'http://localhost:5000/reset-password';
  const sep = base.includes('?') ? '&' : '?';
  return `${base}${sep}token=${encodeURIComponent(token)}`;
};