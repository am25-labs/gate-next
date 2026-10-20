export class GateUnavailableError extends Error {
  readonly code = "gate_unavailable";
  readonly status = 503;

  constructor(message = "Gate is temporarily unavailable", options?: ErrorOptions) {
    super(message, options);
    this.name = "GateUnavailableError";
  }
}
