/**
 * Copyright 2017 The Nakama Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /** A nakama session. */
export interface ISession {
  // Claims
  readonly token: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly username: string;
  readonly user_id: string;
  readonly vars: object;
  // Validate token
  isexpired(currenttime: number): boolean;
}

export class Session {
  public constructor(
    readonly token: string,
    readonly refresh_token: string,
    readonly created_at: number,
    readonly expires_at: number,
    readonly refresh_expires_at: number,
    readonly username: string,
    readonly user_id: string,
    readonly vars: object) {
  }

  isexpired(currenttime: number): boolean {
    return (this.expires_at - currenttime) < 0;
  }

  static restore(jwt: string, refreshToken: string): Session {
    const createdAt = Math.floor(new Date().getTime() / 1000);
    const parts = jwt.split('.');
    if (parts.length != 3) {
      throw 'jwt is not valid.';
    }
    const decoded = JSON.parse(atob(parts[1])); // FIXME: use base64 polyfill for React Native.
    const expiresAt = Math.floor(parseInt(decoded['exp']));

    const refreshParts = refreshToken.split('.');
    if (refreshParts.length != 3) {
      throw 'refreshToken is not valid.';
    }
    const refreshDecoded = JSON.parse(atob(refreshParts[1]));
    const refreshExpiresAt = Math.floor(parseInt(refreshDecoded['exp']));

    return new Session(jwt, refreshToken, createdAt, expiresAt, refreshExpiresAt, decoded['usn'], decoded['uid'], decoded['vrs']);
  }
}
