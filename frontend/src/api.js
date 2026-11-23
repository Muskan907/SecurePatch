// Backend base URL. Override at build time with VITE_API_URL
// (e.g. in Docker), otherwise the local FastAPI dev server is used.
export const API = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");
