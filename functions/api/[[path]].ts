export const onRequest: PagesFunction = async (context) => {
  const { request, env } = context;

  const who = await fetchIdentityFromAccess(request);
  const email = (who?.email || "").toLowerCase();

  const allowed = "soporte.activatepro@gmail.com";

  if (email !== allowed) {
    return json(
      { ok: false, error: "UNAUTHORIZED", email },
      401
    );
  }

  const u = new URL(request.url);

  const incomingPath = u.pathname.replace(/^\/api/, "");

  const routeTable: Record<
    string,
    { methods: Set<string>; targetPath: string }
  > = {
    "/admin/user": {
      methods: new Set(["GET"]),
      targetPath: "/admin/user",
    },

    "/admin/add-tokens": {
      methods: new Set(["POST"]),
      targetPath: "/admin/add-tokens",
    },

    "/admin/reconcile": {
      methods: new Set(["POST"]),
      targetPath: "/admin/reconcile",
    },

    "/admin/reset-user": {
      methods: new Set(["POST"]),
      targetPath: "/admin/reset-user",
    },

    "/admin/purchasers": {
      methods: new Set(["GET"]),
      targetPath: "/admin/purchasers",
    },

    "/admin/api-logs": {
      methods: new Set(["GET"]),
      targetPath: "/admin/api-logs",
    },
  };

  const matched = routeTable[incomingPath];

  if (!matched || !matched.methods.has(request.method)) {
    return json(
      { ok: false, error: "NOT_FOUND", path: incomingPath },
      404
    );
  }

  const workerBase =
    "https://recetassaludablespro.santibernabebb.workers.dev";

  const targetUrl =
    workerBase + matched.targetPath + u.search;

  const ts = Date.now().toString();

  const dataToSign =
    `${ts}:${email}:${request.method}:${matched.targetPath}:${u.search}`;

  const sig = await hmacSha256Hex(
    env.ADMIN_PROXY_SECRET,
    dataToSign
  );

  const headers = new Headers();

  const contentType =
    request.headers.get("content-type");

  if (contentType) {
    headers.set("content-type", contentType);
  }

  const accept = request.headers.get("accept");

  if (accept) {
    headers.set("accept", accept);
  }

  headers.set("x-admin-email", email);
  headers.set("x-admin-ts", ts);
  headers.set("x-admin-sig", sig);

  const body =
    request.method === "GET" ||
    request.method === "HEAD"
      ? undefined
      : await request.arrayBuffer();

  return fetch(targetUrl, {
    method: request.method,
    headers,
    body,
  });
};

function json(data: any, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
}

async function fetchIdentityFromAccess(
  request: Request
) {
  const cookie =
    request.headers.get("cookie") || "";

  const u = new URL(request.url);

  const identityUrl =
    `${u.origin}/cdn-cgi/access/get-identity`;

  const r = await fetch(identityUrl, {
    headers: {
      cookie,
      "user-agent":
        request.headers.get("user-agent") ||
        "",
    },
  });

  if (!r.ok) return null;

  try {
    return await r.json();
  } catch {
    return null;
  }
}

async function hmacSha256Hex(
  secret: string,
  message: string
) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(message)
  );

  return [...new Uint8Array(sig)]
    .map((b) =>
      b.toString(16).padStart(2, "0")
    )
    .join("");
}
