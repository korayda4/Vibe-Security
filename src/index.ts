#!/usr/bin/env node
import { startServer } from './server.js';

startServer().catch((err) => {
  console.error('[vibe-security] Fatal:', err);
  process.exit(1);
});
