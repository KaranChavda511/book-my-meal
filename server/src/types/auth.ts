import { UserRole, IUser } from "./user";

export interface IRegisterPayload {
  name: string;
  email: string;
  password: string;
  role?: UserRole;
}

export interface ILoginPayload {
  email: string;
  password: string;
}

export interface IAuthResponse {
  user: Omit<IUser, "password">;
  accessToken: string;
  refreshToken: string;
}
