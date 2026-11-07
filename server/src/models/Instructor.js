import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
//
// NOTE (security lab): this model is intentionally insecure. Passwords are
// stored in PLAINTEXT (never do this in real code) so that the NoSQL injection
// lab can demonstrate blind $regex password extraction. The apiKey / private
// contact fields are "trophy" data that filter-injection attacks can leak.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    // ⚠️ VULNERABLE (lab): plaintext password, no bcrypt hashing.
    password: { type: String, required: true, select: false },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive "trophy" fields the directory hides but injection can leak.
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);

// SECURITY: hash the password before saving, but only if it changed.
instructorSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Helper: check a plaintext candidate against the stored hash.
instructorSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

export const Instructor = mongoose.model('Instructor', instructorSchema);
