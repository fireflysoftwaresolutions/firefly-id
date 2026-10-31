export function reportFailure(error, lastCompleted, stream = process.stderr) {
  const allowed = new Set(['Error', 'TypeError', 'TimeoutError', 'AssertionError']);
  const kind = allowed.has(error?.name) ? error.name : 'Error';
  stream.write(`Runtime qualification failed (${kind}). Last completed stage: ${lastCompleted}. No raw error or trace is emitted.\n`);
}
