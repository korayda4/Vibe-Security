import sqlInjection from './sqlInjection.js';
import xss from './xss.js';
import weakHashing from './weakHashing.js';

export const rules = {
  sqlInjection,
  xss,
  weakHashing,
};

export default rules;
