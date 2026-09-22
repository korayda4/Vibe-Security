import aiClientExposure from './aiClientExposure.js';
import supabaseServiceKey from './supabaseServiceKey.js';
import serverActionAuth from './serverActionAuth.js';
import promptInjection from './promptInjection.js';
import envSecretLeak from './envSecretLeak.js';

export const rules = {
  aiClientExposure,
  supabaseServiceKey,
  serverActionAuth,
  promptInjection,
  envSecretLeak,
};

export default rules;
