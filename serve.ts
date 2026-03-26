import { createHmac } from "crypto";
import { readFile, stat } from "fs/promises";
import { join, extname } from "path";

const PORT = process.env["PORT"] || "3000";
const API_URL = process.env["KAPABLE_API_URL"] || "https://api.kapable.dev";
const DATA_KEY = process.env["KAPABLE_DATA_KEY"] || "";
const GATE_SECRET = process.env["GATE_SECRET"] || "default-gate-secret";
const DEMO_PASSWORD = process.env["DEMO_PASSWORD"] || "kapable2026";
const OPENROUTER_API_KEY = process.env["OPENROUTER_API_KEY"] || "";
const PUBLIC_DIR = join(import.meta.dir, "public");

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function signToken(payload: Record<string, unknown>): string {
  const data = JSON.stringify(payload);
  const b64 = Buffer.from(data).toString("base64url");
  const sig = createHmac("sha256", GATE_SECRET).update(b64).digest("base64url");
  return `${b64}.${sig}`;
}

function verifyToken(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expectedSig = createHmac("sha256", GATE_SECRET).update(b64).digest("base64url");
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") || "";
  const cookies = header.split(";");
  for (let i = 0; i < cookies.length; i++) {
    const c = cookies[i].trim();
    if (c.startsWith(name + "=")) {
      return c.substring(name.length + 1);
    }
  }
  return null;
}

function loginPage(error?: string): Response {
  const errorHtml = error
    ? `<div class="bg-red-500/20 border border-red-500/30 rounded-lg p-3 mb-4 text-red-300 text-sm">${error}</div>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Resource Harmony Pro — Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    .glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.08); }
    .glow { box-shadow: 0 0 60px rgba(99, 102, 241, 0.15), 0 0 120px rgba(99, 102, 241, 0.05); }
    @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
    .float { animation: float 6s ease-in-out infinite; }
    @keyframes pulse-glow { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
    .pulse-glow { animation: pulse-glow 4s ease-in-out infinite; }
  </style>
</head>
<body class="min-h-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden">
  <div class="absolute inset-0 overflow-hidden">
    <div class="absolute top-1/4 left-1/4 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pulse-glow"></div>
    <div class="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl pulse-glow" style="animation-delay: 2s;"></div>
    <div class="absolute top-1/2 left-1/2 w-64 h-64 bg-cyan-600/5 rounded-full blur-3xl pulse-glow" style="animation-delay: 4s;"></div>
  </div>
  <div class="relative z-10 w-full max-w-md">
    <div class="text-center mb-8 float">
      <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 mb-4 shadow-lg shadow-indigo-500/25">
        <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
      </div>
      <h1 class="text-2xl font-bold text-white tracking-tight">Resource Harmony Pro</h1>
      <p class="text-slate-400 text-sm mt-1">Enterprise Resource Management</p>
    </div>
    <div class="glass rounded-2xl p-8 glow">
      ${errorHtml}
      <form method="POST" action="/__auth/verify" class="space-y-5">
        <div>
          <label class="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Email Address</label>
          <input type="email" name="email" required placeholder="you@company.com"
            class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all text-sm">
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">Password</label>
          <input type="password" name="password" required placeholder="Enter your password"
            class="w-full px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all text-sm">
        </div>
        <button type="submit"
          class="w-full py-3 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-semibold rounded-xl transition-all duration-200 shadow-lg shadow-indigo-600/25 hover:shadow-indigo-500/40 text-sm">
          Sign In
        </button>
      </form>
      <p class="text-center text-slate-500 text-xs mt-6">Secured by Kapable Platform</p>
    </div>
  </div>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function serveStatic(filePath: string): Promise<Response | null> {
  try {
    const info = await stat(filePath);
    if (!info.isFile()) return null;
    const ext = extname(filePath);
    const mime = MIME_TYPES[ext] || "application/octet-stream";
    const content = await readFile(filePath);
    return new Response(content, { headers: { "Content-Type": mime, "Cache-Control": "public, max-age=3600" } });
  } catch {
    return null;
  }
}

const server = Bun.serve({
  port: parseInt(PORT, 10),
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Health check
    if (pathname === "/health") {
      return new Response("ok", { headers: { "Content-Type": "text/plain" } });
    }

    // Auth: login page
    if (pathname === "/__auth/login") {
      return loginPage();
    }

    // Auth: verify credentials
    if (pathname === "/__auth/verify" && request.method === "POST") {
      const formData = await request.formData();
      const email = formData.get("email") as string;
      const password = formData.get("password") as string;

      if (!email || password !== DEMO_PASSWORD) {
        return loginPage("Invalid email or password");
      }

      const token = signToken({
        user_id: createHmac("sha256", GATE_SECRET).update(email).digest("hex").slice(0, 16),
        email,
        project_id: process.env["AUTH_PROJECT_ID"] || "",
        role: "member",
        exp: Date.now() + 24 * 60 * 60 * 1000,
      });

      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `kap_gate_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
        },
      });
    }

    // Auth: logout
    if (pathname === "/__auth/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/__auth/login",
          "Set-Cookie": "kap_gate_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        },
      });
    }

    // Auth gate: check token for non-auth, non-health routes
    if (!pathname.startsWith("/__auth") && pathname !== "/health") {
      const token = getCookie(request, "kap_gate_token");
      if (!token || !verifyToken(token)) {
        return new Response(null, { status: 302, headers: { Location: "/__auth/login" } });
      }
    }

    // SSE Proxy
    if (pathname === "/api/sse") {
      const tables = url.searchParams.get("tables") || "team_members,rh_projects,allocations,clients,monthly_snapshots";
      const sseUrl = new URL(`${API_URL}/v1/sse`);
      sseUrl.searchParams.set("tables", tables);
      sseUrl.searchParams.set("apiKey", DATA_KEY);

      const controller = new AbortController();

      try {
        const upstream = await fetch(sseUrl.toString(), {
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        });

        if (!upstream.ok || !upstream.body) {
          return new Response("SSE unavailable", { status: 502 });
        }

        const { readable, writable } = new TransformStream();
        upstream.body.pipeTo(writable).catch(() => {});
        request.signal.addEventListener("abort", () => controller.abort(), { once: true });

        return new Response(readable, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
            "X-Accel-Buffering": "no",
          },
        });
      } catch {
        return new Response("SSE connection failed", { status: 502 });
      }
    }

    // AI Suggestion endpoint
    if (pathname === "/api/ai/suggest" && request.method === "POST") {
      if (!OPENROUTER_API_KEY) {
        return new Response(JSON.stringify({ error: "AI not configured — set OPENROUTER_API_KEY" }), {
          status: 503, headers: { "Content-Type": "application/json" },
        });
      }
      try {
        const body = await request.json() as {
          members: { name: string; capacity: number; planned: number; utilization: number }[];
          projects: { name: string; tier: string; type: string; totalPlanned: number }[];
          month: string;
        };

        const systemPrompt = `You are a resource allocation optimization advisor for a software consultancy.
You analyze team utilization data and suggest rebalancing to improve efficiency.

Rules:
- Target utilization: 70-85% for developers, 50-70% for management/architects
- Tier 1 projects (revenue-critical) should be fully staffed before tier 2/3
- Internal projects should not exceed 15-20% of any person's capacity
- Never suggest allocating someone to a project they have zero context on without noting the ramp-up cost
- Prefer small adjustments (4-8 hours) over large rebalancing
- Flag anyone over 90% utilization as burnout risk
- Flag anyone under 50% utilization as underutilized

Respond with a JSON object containing a "suggestions" array. Each suggestion has:
- "member": team member name
- "project": project name
- "action": "increase" | "decrease" | "remove" | "add"
- "hours": number of hours to adjust
- "reason": brief explanation (1 sentence)
- "impact": "high" | "medium" | "low"

Also include a "summary" string (2-3 sentences) and a "risks" array of strings.`;

        const userPrompt = `Analyze this resource allocation for ${body.month} and suggest optimizations:

TEAM UTILIZATION:
${body.members.map(m => `- ${m.name}: ${m.planned}h / ${m.capacity}h (${m.utilization.toFixed(0)}% utilized)`).join('\n')}

PROJECT ALLOCATIONS:
${body.projects.map(p => `- ${p.name} [${p.tier}, ${p.type}]: ${p.totalPlanned}h total`).join('\n')}

Suggest specific rebalancing moves to optimize utilization and project coverage.`;

        const aiResp = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
            "HTTP-Referer": "https://resource-harmony-spec.kapable.run",
            "X-Title": "Resource Harmony Pro",
          },
          body: JSON.stringify({
            model: "google/gemini-2.0-flash-001",
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userPrompt },
            ],
            max_tokens: 2000,
            temperature: 0.3,
            response_format: { type: "json_object" },
          }),
        });

        if (!aiResp.ok) {
          const errText = await aiResp.text();
          console.error("AI API error:", aiResp.status, errText);
          return new Response(JSON.stringify({ error: "AI service error" }), {
            status: 502, headers: { "Content-Type": "application/json" },
          });
        }

        const aiData = await aiResp.json() as { choices: { message: { content: string } }[] };
        const content = aiData.choices?.[0]?.message?.content || "{}";
        // Parse the JSON from the response
        let suggestions;
        try {
          suggestions = JSON.parse(content);
        } catch {
          // Try to extract JSON from markdown code blocks
          const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
          suggestions = jsonMatch ? JSON.parse(jsonMatch[1]) : { suggestions: [], summary: content, risks: [] };
        }

        return new Response(JSON.stringify(suggestions), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        console.error("AI suggestion error:", err);
        return new Response(JSON.stringify({ error: "Failed to generate suggestions" }), {
          status: 500, headers: { "Content-Type": "application/json" },
        });
      }
    }

    // BFF Data Proxy: /api/* -> API_URL/v1/*
    if (pathname.startsWith("/api/")) {
      const apiPath = pathname.replace(/^\/api/, "/v1");
      const apiUrl = new URL(apiPath, API_URL);
      apiUrl.search = url.search;

      const headers: Record<string, string> = {
        "x-api-key": DATA_KEY,
      };

      const contentType = request.headers.get("content-type");
      if (contentType) headers["content-type"] = contentType;

      try {
        const resp = await fetch(apiUrl.toString(), {
          method: request.method,
          headers,
          body: request.method !== "GET" && request.method !== "HEAD" ? await request.text() : undefined,
        });

        const respHeaders = new Headers();
        resp.headers.forEach((v, k) => respHeaders.set(k, v));
        respHeaders.set("Access-Control-Allow-Origin", "*");

        return new Response(resp.body, {
          status: resp.status,
          headers: respHeaders,
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Upstream API error" }), {
          status: 502,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Static file serving
    const filePath = join(PUBLIC_DIR, pathname === "/" ? "index.html" : pathname);
    const staticResp = await serveStatic(filePath);
    if (staticResp) return staticResp;

    // SPA fallback
    const indexPath = join(PUBLIC_DIR, "index.html");
    const indexResp = await serveStatic(indexPath);
    if (indexResp) return indexResp;

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`Resource Harmony Pro listening on http://localhost:${server.port}`);
