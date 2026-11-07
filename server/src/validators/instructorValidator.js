import Joi from 'joi';

// SECURITY: Joi describes EXACTLY what valid input looks like.
// Anything that doesn't match (wrong type, extra fields, injected objects)
// is rejected before it ever reaches Mongoose.

// Rules for the login body.
export const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(100).required(),
  password: Joi.string().min(1).max(200).required()
});

// Rules for the search query.
// Only these public fields may be used to filter, and each must be a string.
export const searchSchema = Joi.object({
  name: Joi.string().trim().max(100),
  department: Joi.string().trim().max(100),
  role: Joi.string().trim().max(100)
});