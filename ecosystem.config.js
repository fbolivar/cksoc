/**
 * Configuracion PM2 para el backend SOC PNNC.
 * El frontend se compila (vite build) y se sirve como estatico desde Nginx,
 * por lo que NO necesita un proceso PM2 propio.
 *
 * Uso:
 *   cd backend && npm run build
 *   pm2 start ecosystem.config.js
 *   pm2 save
 */
module.exports = {
  apps: [
    {
      name: 'soc-backend',
      cwd: './backend',
      script: 'dist/index.js',
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
      },
      max_memory_restart: '300M',
      out_file: './logs/backend-out.log',
      error_file: './logs/backend-error.log',
      merge_logs: true,
      time: true,
    },
  ],
};
