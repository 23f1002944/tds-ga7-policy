import { handleRequest } from './policy.js';

export default {
  fetch: (request) => handleRequest(request),
};
