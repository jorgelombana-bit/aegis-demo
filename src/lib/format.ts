/**
 * Pure helper for JSON scalar formatting. Kept in its own module so the
 * `react-refresh/only-export-components` rule stays happy with JsonView.tsx.
 */
export function formatJsonScalar(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'bigint') return `${value.toString()}n`;
  if (value instanceof Uint8Array) return `Uint8Array(${value.length})`;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}
