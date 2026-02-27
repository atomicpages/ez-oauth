export class OAuthClientError extends Error {
  readonly reason: string;

  constructor(
    message: string,
    { cause, reason }: { cause?: any; reason?: any },
  ) {
    super(message);
    this.name = "OAuthClientError";
    this.cause = cause;
    this.reason = reason;
  }
}
