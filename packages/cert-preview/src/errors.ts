import type { ErrorCode } from "./generated/ErrorCode";
import type { ErrorPayload } from "./generated/ErrorPayload";

/**
 * Error thrown by every `CertViewApi` method when the core rejects an input.
 *
 * It wraps the structured {@link ErrorPayload} the Rust side produced, so
 * callers can branch on the stable `code` instead of matching message text.
 */
export class CertViewError extends Error {
  /** Stable machine-readable discriminator (e.g. `"DER_DECODE"`). */
  readonly code: ErrorCode;
  /** Byte offset in the input when the error could be localised, else `null`. */
  readonly offset: number | null;
  /** The raw payload as handed over the boundary. */
  readonly payload: ErrorPayload;

  constructor(payload: ErrorPayload) {
    super(payload.message);
    this.name = "CertViewError";
    this.code = payload.code;
    // ts-rs omits an `Option` field when it is `None`, so normalise to `null`
    // to keep the public type (`number | null`) honest at runtime.
    this.offset = payload.offset ?? null;
    this.payload = payload;
  }
}

function isErrorPayload(value: unknown): value is ErrorPayload {
  if (typeof value !== "object" || value === null) return false;
  const rec = value as Record<string, unknown>;
  return (
    typeof rec.code === "string" &&
    typeof rec.message === "string" &&
    ("offset" in rec)
  );
}

/**
 * Normalise anything a call might throw into a {@link CertViewError}.
 *
 * A recognised {@link ErrorPayload} is preserved as-is; a plain `Error` or any
 * other value becomes a `UNKNOWN_FORMAT` carrier so the caller still gets a
 * typed error to branch on.
 */
export function asCertViewError(value: unknown): CertViewError {
  if (isErrorPayload(value)) {
    return new CertViewError(value);
  }
  const message = value instanceof Error ? value.message : String(value);
  return new CertViewError({
    code: "UNKNOWN_FORMAT" as ErrorCode,
    message,
    offset: null,
  });
}
