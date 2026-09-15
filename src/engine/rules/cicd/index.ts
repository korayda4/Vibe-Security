import dependencies from './dependencies.js';
import secrets from './secrets.js';
import dockerfile from './dockerfile.js';

export const rules = {
  dependencies,
  secrets,
  dockerfile,
};

export default rules;
