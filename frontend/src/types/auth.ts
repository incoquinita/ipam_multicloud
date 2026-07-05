/**
 * Auth types — mirror the backend auth schemas
 * (`app/schemas/auth.py`) so credentials and tokens are parsed
 * into a trusted shape at the API boundary.
 */

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthUser {
  id: string;
  email: string;
  username: string;
  is_active: boolean;
  is_superuser: boolean;
}
