import idor from './idor.js';
import hashing from './hashing.js';
import jwt from './jwt.js';
import sqlInjection from './sqlInjection.js';
import inputValidation from './inputValidation.js';
import rateLimit from './rateLimit.js';
import fileUpload from './fileUpload.js';
import tokenInUrl from './tokenInUrl.js';
import tokenExpiry from './tokenExpiry.js';

export const rules = {
  idor,
  hashing,
  jwt,
  sqlInjection,
  inputValidation,
  rateLimit,
  fileUpload,
  tokenInUrl,
  tokenExpiry,
};

export default rules;
