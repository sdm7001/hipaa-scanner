module.exports = {
  apps: [
    {
      name: 'hipaa-api',
      interpreter: '/var/www/hipaa-scanner/backend/venv/bin/python',
      script: '/var/www/hipaa-scanner/backend/venv/bin/uvicorn',
      args: 'app.main:app --host 127.0.0.1 --port 8000 --workers 2 --log-level info',
      cwd: '/var/www/hipaa-scanner/backend',
      env: {
        PYTHONPATH: '/var/www/hipaa-scanner/backend',
      },
      error_file: '/var/log/hipaa-scanner/api-error.log',
      out_file: '/var/log/hipaa-scanner/api-out.log',
      merge_logs: true,
      max_restarts: 10,
    },
  ],
}
