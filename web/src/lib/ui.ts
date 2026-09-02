// Small helpers shared across route components — kept out of any one route
// so KeyMap, Privacy, and Files stay in sync on how key state is colored and
// how a Blob becomes a browser download.

export const STATE_DOT: Record<string, string> = {
  active: "#7fbf7f",
  pending: "#9397ab",
  deprecated: "#d9b46a",
  revoked: "#d97878",
  destroyed: "#595d6c",
};

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
