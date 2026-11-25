import { request } from "node:https";

/** Seconds to add to local time so it matches Google's server clock (as the original extension did). */
export function fetchOffset(url = "https://www.google.com/generate_204", timeoutMs = 8000): Promise<number> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const req = request(url, { method: "HEAD", timeout: timeoutMs }, (res) => {
      res.resume();
      const date = res.headers.date;
      if (!date) return reject(new Error("Server sent no Date header"));
      const local = (started + Date.now()) / 2;
      const offset = Math.round((new Date(date).getTime() - local) / 1000);
      if (!Number.isFinite(offset)) return reject(new Error("Server sent an invalid Date header"));
      resolve(offset);
    });
    req.on("timeout", () => req.destroy(new Error("Clock sync timed out")));
    req.on("error", reject);
    req.end();
  });
}
