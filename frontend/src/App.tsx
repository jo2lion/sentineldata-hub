import { useQuery } from "@tanstack/react-query";
import type { ThreatIndicator } from "./types/threat";

// --------------------------------------------------------------------------- #
// SECURITY — read before this goes anywhere near a real deployment.
//
// `VITE_API_KEY` is compiled directly into the static JS bundle Vite ships to
// the browser. It is NOT a server-side secret once this is deployed anywhere
// public — anyone can read it out of dev tools / view-source on the built
// assets. This is wired up so `npm run dev` talks to the real backend today;
// it is explicitly not the production-appropriate design. This was flagged
// and left open in chat: decide whether (a) this stays an internal tool
// behind a network/VPN boundary and the key is defense-in-depth only, or
// (b) a backend-for-frontend holds the real key server-side and the browser
// authenticates via session/cookie instead. Do not skip this decision.
// --------------------------------------------------------------------------- #

const API_KEY = import.meta.env.VITE_API_KEY;

async function fetchThreats(): Promise<ThreatIndicator[]> {
  const response = await fetch("/api/v1/threats", {
    headers: API_KEY ? { "X-API-Key": API_KEY } : {},
  });

  if (!response.ok) {
    throw new Error(`GET /api/v1/threats failed with status ${response.status}: ${response.statusText}`);
  }

  return (await response.json()) as ThreatIndicator[];
}

function useThreats() {
  return useQuery({
    queryKey: ["threats"],
    queryFn: fetchThreats,
    refetchInterval: 30_000,
  });
}

type PillTone = "ok" | "warning" | "critical" | "muted";

function StatusPill({ tone, label }: { tone: PillTone; label: string }) {
  const toneClass: Record<PillTone, string> = {
    ok: "bg-signal-ok/15 text-signal-ok border-signal-ok/40",
    warning: "bg-signal-warning/15 text-signal-warning border-signal-warning/40",
    critical: "bg-signal-critical/15 text-signal-critical border-signal-critical/40",
    muted: "bg-signal-muted/15 text-signal-muted border-signal-muted/40",
  };

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${toneClass[tone]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}

function OutageBanner() {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-lg border border-signal-critical/50 bg-signal-critical/10 px-4 py-3 text-signal-critical"
    >
      <span aria-hidden className="text-lg font-bold leading-none">
        ⚠
      </span>
      <div>
        <p className="font-semibold">Zero indicators returned this cycle.</p>
        <p className="text-sm text-signal-critical/80">
          Every configured OSINT feed may be unreachable, or nothing survived schema
          validation this cycle. Check{" "}
          <code className="font-mono">ingestion.wholesale_outage_empty_cycle</code> in the
          backend logs before assuming there is simply no active threat data right now.
        </p>
      </div>
    </div>
  );
}

function riskTone(riskScore: number): string {
  if (riskScore >= 5.0) return "text-signal-critical";
  if (riskScore >= 4.0) return "text-signal-warning";
  if (riskScore >= 3.0) return "text-signal-warning/70";
  return "text-signal-ok";
}

export default function App() {
  const { data, isLoading, isError, error, dataUpdatedAt } = useThreats();

  return (
    <div className="min-h-screen bg-grid-950 text-grid-100">
      <header className="border-b border-grid-700 px-6 py-4">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-grid-100">SentinelData Hub</h1>
            <p className="text-xs text-grid-300">OSINT / CVE Threat Indicator Grid</p>
          </div>
          <StatusPill
            tone={isError ? "critical" : isLoading ? "muted" : "ok"}
            label={isError ? "Connection Fault" : isLoading ? "Syncing" : "Live"}
          />
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        {isLoading && <p className="text-sm text-grid-300">Running ingestion cycle…</p>}

        {isError && (
          <div
            role="alert"
            className="rounded-lg border border-signal-critical/50 bg-signal-critical/10 px-4 py-3 text-signal-critical"
          >
            <p className="font-semibold">Failed to reach the ingestion API.</p>
            <p className="text-sm text-signal-critical/80">
              {error instanceof Error ? error.message : "Unknown transport error."}
            </p>
          </div>
        )}

        {!isLoading && !isError && data && data.length === 0 && <OutageBanner />}

        {!isLoading && !isError && data && data.length > 0 && (
          <>
            <p className="mb-4 text-xs text-grid-300">
              {data.length} indicator{data.length === 1 ? "" : "s"} · last synced{" "}
              {new Date(dataUpdatedAt).toLocaleTimeString()}
            </p>
            <div className="overflow-hidden rounded-lg border border-grid-700">
              <table className="w-full text-left text-sm">
                <thead className="bg-grid-800 text-grid-300">
                  <tr>
                    <th className="px-4 py-3 font-medium">Title</th>
                    <th className="px-4 py-3 font-medium">Description</th>
                    <th className="px-4 py-3 font-medium">Source</th>
                    <th className="px-4 py-3 font-medium">Observed At</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-grid-700">
                  {data.map((indicator) => (
                    <tr key={indicator.id} className="hover:bg-grid-800/60 align-top">
                      <td className="px-4 py-3 font-mono text-grid-100 whitespace-nowrap">{indicator.title}</td>
                      <td className="px-4 py-3 text-grid-300">
                        {/* Safe HTML Ingestion Rendering Core Block */}
                        <div 
                          className="prose prose-invert text-sm max-w-none space-y-2 
                                     [&_a]:text-blue-400 [&_a]:underline hover:[&_a]:text-blue-300
                                     [&_ul]:list-disc [&_ul]:pl-5 [&_li]:mt-1"
                          dangerouslySetInnerHTML={{ __html: indicator.description }} 
                        />
                      </td>
                      <td className="px-4 py-3 text-grid-300">
                        <a
                          href={indicator.source_url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="underline decoration-grid-500 hover:text-grid-100"
                        >
                          source
                        </a>
                      </td>
                      <td className="px-4 py-3 text-grid-300 whitespace-nowrap">
                        {new Date(indicator.observed_at).toLocaleString()}
                      </td>
                      <td className={`px-4 py-3 font-mono ${riskTone(indicator.risk_score)}`}>
                        {indicator.risk_score.toFixed(1)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </main>
    </div>
  );
}