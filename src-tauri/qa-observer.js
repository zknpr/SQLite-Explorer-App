;(() => {
  // Installed before page startup, only in the explicitly enabled QA build.
  // Observe errors without replacing the shell bridge or changing CSP.
  const records = { errors: [], rejections: [], consoleErrors: [], csp: [] };
  window.__SQLITE_QA_OBSERVATIONS__ = records;
  window.addEventListener('error', event => {
    records.errors.push({ message: event.message, file: event.filename, line: event.lineno });
  });
  window.addEventListener('unhandledrejection', event => {
    records.rejections.push(String(event.reason?.stack ?? event.reason));
  });
  window.addEventListener('securitypolicyviolation', event => {
    records.csp.push({ directive: event.effectiveDirective, blocked: event.blockedURI });
  });
  const originalError = console.error.bind(console);
  console.error = (...args) => {
    records.consoleErrors.push(args.map(value => String(value)).join(' '));
    originalError(...args);
  };
})();
