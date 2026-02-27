import * as client from "openid-client";

type OAuthStateOptions = {
  state: string;
  nonce: string;
  pkce: string;
  codeVerifier: string;
};

export class OAuthState {
  static CODE_CHALLENGE_METHOD = "S256";

  readonly state: string;
  readonly nonce: string;
  _pkce: string | undefined;
  readonly codeVerifier: string;

  constructor(options?: Partial<OAuthStateOptions> | null) {
    this.state = options?.state ?? client.randomState();
    this.nonce = options?.nonce ?? client.randomNonce();

    this.codeVerifier =
      options?.codeVerifier ?? client.randomPKCECodeVerifier();

    this._pkce = options?.pkce;
  }

  async getCodeChallenge(): Promise<string> {
    if (this._pkce) {
      return this._pkce;
    }

    this._pkce = await client.calculatePKCECodeChallenge(this.codeVerifier);

    return this._pkce;
  }

  get pkce(): string | undefined {
    return this._pkce;
  }

  toJSON() {
    return {
      name: this.constructor.name,
      state: this.state,
      nonce: this.nonce,
      pkce: this.pkce,
      codeVerifier: this.codeVerifier,
    };
  }

  /**
   * A stringified JSON representation of the state. You will NOT
   * see `[object Object]` as the output 🫠
   */
  toString(): string {
    return JSON.stringify(this.toJSON());
  }

  static fromJSON(json: ReturnType<OAuthState["toJSON"]>): OAuthState {
    return new OAuthState(json);
  }
}
