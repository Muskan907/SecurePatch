import { useEffect, useState } from "react";
import { API } from "./api";

let rulesPromise = null;

// Bandit rule catalog, fetched once and shared by every component.
export function useBanditRules() {
  const [data, setData] = useState(null);
  useEffect(() => {
    rulesPromise =
      rulesPromise ||
      fetch(`${API}/api/bandit/rules`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null);
    let alive = true;
    rulesPromise.then((d) => {
      if (!d) rulesPromise = null; // allow a retry later
      if (alive) setData(d);
    });
    return () => {
      alive = false;
    };
  }, []);
  return data;
}
