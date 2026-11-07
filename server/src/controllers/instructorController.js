
import { loginSchema, searchSchema } from '../validators/instructorValidator.js';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
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

    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.

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
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
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
    // SECURITY: only allow filtering by the three public fields, each a string.
    const { error, value } = searchSchema.validate(req.query);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    // SECURITY: build the filter ourselves from validated values only.
    // String(...) guarantees a primitive string, never an object/operator.
    const filter = {};
    if (value.name !== undefined) filter.name = String(value.name);
    if (value.department !== undefined) filter.department = String(value.department);
    if (value.role !== undefined) filter.role = String(value.role);

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
