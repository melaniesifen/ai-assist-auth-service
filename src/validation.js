export function requireNonEmptyString(value, field) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} must be a non-empty string.`);
  }
  return value;
}

export function requireDate(value, field) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new TypeError(`${field} must be a valid date.`);
  }
  return date;
}

export function cloneDate(value) {
  return value ? new Date(value.getTime()) : null;
}

export function toIso(value) {
  return value instanceof Date ? value.toISOString() : null;
}
