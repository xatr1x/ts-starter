import { Document, Schema, Model, model, Error } from "mongoose";
import bcryptjs from "bcryptjs";

export interface IUser extends Document {
  username: string;
  password: string;
}

export const userSchema: Schema = new Schema({
  username: String,
  password: String,
});

userSchema.methods.comparePassword = function (candidatePassword: string, callback: any) {
  bcryptjs.compare(candidatePassword, this.password, (error: Error, result: Boolean) => {
    callback(error, result);
  });
};

export const User: Model<IUser> = model<IUser>("User", userSchema);
