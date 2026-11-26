export function init() {
  if (!process.env.TURBO_TELEMETRY_DISABLED) {
    console.log("turbo telemetry is enabled");
  }
}
