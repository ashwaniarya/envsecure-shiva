// Keeps secrets out of crash output: no diagnostic reports, and no error text or stack in fatal messages.
export function harden() {
  try {
    process.report.reportOnFatalError = false;
    process.report.reportOnUncaughtException = false;
    process.report.reportOnSignal = false;
  } catch { /* report API unavailable */ }
  const die = () => { process.stderr.write("shiva: fatal error (details withheld)\n"); process.exit(70); };
  process.on("uncaughtException", die);
  process.on("unhandledRejection", die);
}

export function zero(buf) { if (Buffer.isBuffer(buf)) buf.fill(0); }
