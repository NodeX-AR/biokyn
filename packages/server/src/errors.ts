/** Errors that map directly to an HTTP status. Bodies never contain risk information. */
export class BioKynHttpError extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly retryAfterSec?: number) {
    super(code);
    this.name = 'BioKynHttpError';
  }
}
