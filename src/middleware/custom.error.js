class HttpError extends Error {
  constructor(code, message) {
    super();
    this.code = code || 500;
    this.message = message || 'Internal server error';
  }
}

module.exports = {
  HttpError,
};
