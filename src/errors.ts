/** An error raised on purpose for the caller (bad input, limits, quote rules). Its message is safe to show. */
export class ToolError extends Error {
  constructor(message: string) { super(message); this.name = 'ToolError'; }
}
