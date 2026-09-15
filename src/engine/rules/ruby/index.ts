import sqlInjection from './sqlInjection.js';
import strongParams from './strongParams.js';
import xss from './xss.js';

export const rules = {
  sqlInjection,
  strongParams,
  xss,
};

export default rules;
