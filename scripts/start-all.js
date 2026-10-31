/**
 * scripts/start-all.js
 * Menjalankan ketiga aplikasi secara bersamaan.
 */
const { spawn } = require('child_process');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');

const services = [
  { name: 'API Gateway', script: path.join(rootDir, 'gateway', 'index.js') },
  { name: 'Grade Service', script: path.join(rootDir, 'grade-service', 'index.js') },
  { name: 'Transcript Service', script: path.join(rootDir, 'transcript-service', 'index.js') },
];

const processes = [];

for (const svc of services) {
  const proc = spawn('node', [svc.script], {
    cwd: rootDir,
    stdio: 'pipe',
    env: { ...process.env },
  });

  proc.stdout.on('data', (data) => {
    process.stdout.write(`[${svc.name}] ${data}`);
  });

  proc.stderr.on('data', (data) => {
    process.stderr.write(`[${svc.name} ERR] ${data}`);
  });

  proc.on('close', (code) => {
    console.log(`[${svc.name}] proses berhenti dengan kode ${code}`);
  });

  processes.push(proc);
}

// Tangani CTRL+C
process.on('SIGINT', () => {
  console.log('\nMenghentikan semua service...');
  for (const proc of processes) {
    proc.kill('SIGINT');
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  for (const proc of processes) {
    proc.kill('SIGTERM');
  }
  process.exit(0);
});

console.log('Semua service dimulai. Tekan CTRL+C untuk menghentikan.');
