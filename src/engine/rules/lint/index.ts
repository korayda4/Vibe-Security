import emptyCatch from './emptyCatch.js';
import floatingPromise from './floatingPromise.js';
import typeBypass from './typeBypass.js';
import jsonSyntax from './jsonSyntax.js';
import resourceLeak from './resourceLeak.js';

export const rules = {
  emptyCatch,
  floatingPromise,
  typeBypass,
  jsonSyntax,
  resourceLeak,
};

export default rules;
