/**
 * A generic Error that all other JOSE specific Error subclasses extend.
 *
 * @example
 *
 * Checking thrown error is a JOSE one
 *
 * ```js
 * if (err instanceof jose.errors.JOSEError) {
 *   // ...
 * }
 * ```
 */
export class JOSEError extends Error {
  /**
   * A unique error code for the particular error subclass.
   *
   * @ignore
   */
  static get code(): string {
    return 'ERR_JOSE_GENERIC'
  }

  /** A unique error code for this particular error subclass. */
  code = 'ERR_JOSE_GENERIC'

  /** @ignore */
  constructor(message?: string) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace?.(this, this.constructor)
  }
}

export class JOSENotSupported extends JOSEError {
  /** @ignore */
  static get code(): 'ERR_JOSE_NOT_SUPPORTED' {
    return 'ERR_JOSE_NOT_SUPPORTED'
  }

  code = 'ERR_JOSE_NOT_SUPPORTED'
}
