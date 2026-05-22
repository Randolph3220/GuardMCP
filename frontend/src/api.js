export async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message = payload?.detail || payload?.error || response.statusText;
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }
  return payload;
}

export function guardRpc(token, id, method, params = {}) {
  return requestJson("/guard/mcp", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  });
}

export function rpcResult(response) {
  return response?.result || response?.error || response;
}
