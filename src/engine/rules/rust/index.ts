import unsafeExpect from './unsafeExpect.js';
import sqlInjection from './sqlInjection.js';
import secretInCode from './secretInCode.js';

export const rules = {
  unsafeExpect,
  sqlInjection,
  secretInCode,
};

export default rules;
