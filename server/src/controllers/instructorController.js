import { loginSchema, searchSchema } from '../validators/instructorValidator.js';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  hardened against NoSQL injection
// =============================================================================
//
// Defenses in this file (defense in depth):
//   1. express-mongo-sanitize (in app.js) strips any key with `$` or `.`.
//   2. Joi validates the shape/type of input before it reaches Mongoose.
//   3. Login looks up by username only, then verifies the password with bcrypt.
//   4. Passwords are bcrypt-hashed (see the Instructor model).
//   5. Secret fields (password/apiKey/private*) are never returned.
// =============================================================================

// Only non-sensitive fields are ever returned to the client.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    // SECURITY: validate shape/type first. Rejects objects, operators, missing fields.
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { username, password } = value;

    // SECURITY: look up by username ONLY, then verify the password with bcrypt.
    // The password is never part of the query, so it can't be injected or regex-probed.
    const instructor = await Instructor.findOne({ username }).select('+password');
    if (!instructor || !(await instructor.comparePassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // SECURITY: never trust req.query. Ignore anything that isn't one of the
    // three public string fields. stripUnknown drops unexpected keys (e.g.
    // injected ones) instead of rejecting; convert:false keeps non-strings out.
    const { value } = searchSchema.validate(req.query, {
      stripUnknown: true,
      convert: false
    });

    // SECURITY: build the filter ourselves, only from clean string values.
    const filter = {};
    if (typeof value?.name === 'string') filter.name = value.name;
    if (typeof value?.department === 'string') filter.department = value.department;
    if (typeof value?.role === 'string') filter.role = value.role;

    // SECURITY: return only public fields (no password / apiKey / private info).
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}