import xss from './xss.js';
import cookies from './cookies.js';
import envVars from './envVars.js';
import sourceMaps from './sourceMaps.js';
import clickjacking from './clickjacking.js';
import evalRule from './eval.js';

export const rules = {
  xss,
  cookies,
  envVars,
  sourceMaps,
  clickjacking,
  eval: evalRule,
};

export default rules;
