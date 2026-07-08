import { useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import type { DashboardMetrics, ThreatIndicator } from "./types/threat";

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

function authHeaders(): HeadersInit {
  return API_KEY ? { "X-API-Key": API_KEY } : {};
}

async function fetchThreats(): Promise<ThreatIndicator[]> {
  const response = await fetch("/api/v1/threats", { headers: authHeaders() });

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

async function fetchMetrics(): Promise<DashboardMetrics> {
  const response = await fetch("/api/v1/metrics", { headers: authHeaders() });

  if (!response.ok) {
    throw new Error(`GET /api/v1/metrics failed with status ${response.status}: ${response.statusText}`);
  }

  // Single aggregate object, not a list -- GET /api/v1/metrics returns one
  // DashboardMetrics per request, computed server-side over the whole table.
  return (await response.json()) as DashboardMetrics;
}

function useMetrics() {
  return useQuery({
    queryKey: ["metrics"],
    queryFn: fetchMetrics,
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
  // Explicit, high-visibility handling of the len(indicators) == 0 case —
  // matches the backend's deliberate design: total outage returns 200 with
  // an empty list, not an error. This is distinct from "the search/filter
  // matched nothing" below -- conflating the two would hide a real backend
  // outage behind what looks like a harmless empty filter result.
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

function NoFilterMatchesNotice({ totalCount }: { totalCount: number }) {
  // Deliberately separate from OutageBanner. This fires when the backend
  // returned real data but the client-side search/risk filter narrowed it
  // to zero rows -- a completely different situation from a wholesale feed
  // outage, and one that should never be styled as an error.
  return (
    <p className="rounded-lg border border-grid-700 bg-grid-900/40 px-4 py-6 text-center text-sm text-grid-300">
      No indicators match the current search/filter. {totalCount} total indicator
      {totalCount === 1 ? "" : "s"} loaded.
    </p>
  );
}

// risk_score is bounded 1.0-5.0 and, per pipeline.py's _process_batch, only ever
// actually takes the discrete values {1.0, 3.0, 4.0, 5.0} today. Thresholds are
// set to match that bucketing, not an arbitrary continuous scale.
function riskTone(riskScore: number): string {
  if (riskScore >= 5.0) return "text-signal-critical";
  if (riskScore >= 4.0) return "text-signal-warning";
  if (riskScore >= 3.0) return "text-signal-warning/70";
  return "text-signal-ok";
}

// --------------------------------------------------------------------------- #
// Defensive runtime guard
//
// ThreatIndicator.description is typed as a required `string` (mirroring the
// Pydantic contract, which does require it) -- that's a compile-time
// promise, not a runtime one. A bad row, a partial migration, or any future
// write path that bypasses ThreatIndicator's own validator could still hand
// the frontend a null/undefined value that matches the JSON shape but
// violates the contract. Guarding here, not by loosening the TS type: the
// type stays honest about what the contract promises; this is defense
// against the contract being violated, not a redefinition of it.
//
// Tag-stripping does not do any XSS-relevant work by itself -- the result
// is rendered as plain JSX text ({cleansedDescription}), which React escapes
// regardless of whether it contains "<" characters. This function's job is
// null-safety and display hygiene only. It must never be passed to
// dangerouslySetInnerHTML -- stripping tags with a regex is not a sanitizer
// (it's bypassable by malformed/nested markup) and was exactly the wrong
// tool for the dangerouslySetInnerHTML XSS found and removed from this file
// two passes ago.
// --------------------------------------------------------------------------- #

function stripHtmlTags(htmlString: string | undefined | null): string {
  if (!htmlString) return "";
  return htmlString.replace(/<\/?[^>]+(>|$)/g, " ").trim();
}

// --------------------------------------------------------------------------- #
// Client-side search + risk filter
//
// The risk filter dropdown exposes 3 buckets (critical/warning/ok), not the
// 4 tiers riskTone() renders (critical/high/medium/baseline). "warning" here
// intentionally collapses both the 4.0 ("high") and 3.0 ("medium") tiers
// into one bucket, since there's no separate "medium" option in the spec.
// Stated here explicitly rather than silently decided.
// --------------------------------------------------------------------------- #

type RiskFilter = "all" | "critical" | "warning" | "ok";

const RISK_FILTER_OPTIONS: ReadonlyArray<{ value: RiskFilter; label: string }> = [
  { value: "all", label: "All Risk Levels" },
  { value: "critical", label: "Critical (≥5.0)" },
  { value: "warning", label: "Warning (3.0–4.9)" },
  { value: "ok", label: "Baseline (<3.0)" },
];

function matchesRiskFilter(riskScore: number, filter: RiskFilter): boolean {
  switch (filter) {
    case "all":
      return true;
    case "critical":
      return riskScore >= 5.0;
    case "warning":
      return riskScore >= 3.0 && riskScore < 5.0;
    case "ok":
      return riskScore < 3.0;
  }
}

// --------------------------------------------------------------------------- #
// KPI dashboard cards
//
// Reuses the exact signal-* opacity-scaled token pattern already proven to
// compile in StatusPill/OutageBanner above (bg-signal-x/NN, text-signal-x,
// border-signal-x/NN) instead of inventing new arbitrary-value shadow/glow
// utilities referencing CSS custom properties whose names aren't visible
// from this file (index.css's @theme block). Known-good tokens over a
// guessed "glow" effect that might silently fail to compile.
// --------------------------------------------------------------------------- #

type SignalTone = "ok" | "warning" | "critical";

const KPI_CARD_TONE_CLASS: Record<SignalTone, string> = {
  ok: "border-signal-ok/30 bg-signal-ok/5",
  warning: "border-signal-warning/30 bg-signal-warning/5",
  critical: "border-signal-critical/30 bg-signal-critical/5",
};

const KPI_VALUE_TONE_CLASS: Record<SignalTone, string> = {
  ok: "text-signal-ok",
  warning: "text-signal-warning",
  critical: "text-signal-critical",
};

function KpiCard({ label, value, tone }: { label: string; value: string; tone: SignalTone }) {
  return (
    <div className={`rounded-lg border px-5 py-4 ${KPI_CARD_TONE_CLASS[tone]}`}>
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">{label}</p>
      <p className={`mt-2 font-mono text-3xl font-bold ${KPI_VALUE_TONE_CLASS[tone]}`}>{value}</p>
    </div>
  );
}

function KpiCardSkeleton({ label }: { label: string }) {
  return (
    <div className="rounded-lg border border-grid-700 bg-grid-900/40 px-5 py-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">{label}</p>
      <div className="mt-2 h-8 w-16 animate-pulse rounded bg-grid-700/60" />
    </div>
  );
}

function MetricsPanel() {
  const { data: metrics, isLoading, isError, error } = useMetrics();

  if (isLoading) {
    return (
      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
        <KpiCardSkeleton label="Total Indicators" />
        <KpiCardSkeleton label="Critical" />
        <KpiCardSkeleton label="High" />
      </div>
    );
  }

  if (isError || !metrics) {
    return (
      <p className="mb-6 text-xs text-signal-critical/80">
        Failed to load dashboard metrics
        {error instanceof Error ? `: ${error.message}` : "."}
      </p>
    );
  }

  return (
    <div className="mb-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <KpiCard label="Total Indicators" value={metrics.total_indicators.toString()} tone="ok" />
        <KpiCard label="Critical" value={metrics.critical_count.toString()} tone="critical" />
        <KpiCard label="High" value={metrics.high_count.toString()} tone="warning" />
      </div>
      <p className="mt-2 text-xs text-grid-400">
        Last DB write:{" "}
        {metrics.latest_ingestion_time
          ? new Date(metrics.latest_ingestion_time).toLocaleString()
          : "no indicators ingested yet."}
      </p>
    </div>
  );
}

export default function App() {
  const { data, isLoading, isError, error, dataUpdatedAt } = useThreats();

  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");

  // Derived, not stored -- filteredData is always a pure function of
  // (data, searchQuery, riskFilter). useMemo avoids recomputing the filter
  // pass on unrelated re-renders (e.g. the metrics query refetching).
  const filteredData = useMemo(() => {
    if (!data) return [];
    const normalizedQuery = searchQuery.trim().toLowerCase();
    return data.filter((indicator) => {
      if (!matchesRiskFilter(indicator.risk_score, riskFilter)) return false;
      if (!normalizedQuery) return true;
      // Both sides guarded against a null/undefined field slipping past the
      // TS contract at runtime -- see stripHtmlTags' comment above for why.
      const safeTitle = indicator.title ?? "";
      const safeDescription = stripHtmlTags(indicator.description);
      return (
        safeTitle.toLowerCase().includes(normalizedQuery) ||
        safeDescription.toLowerCase().includes(normalizedQuery)
      );
    });
  }, [data, searchQuery, riskFilter]);

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
        <MetricsPanel />

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
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-1 flex-col gap-3 sm:flex-row sm:items-center">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setSearchQuery(event.target.value)}
                  placeholder="Search title or description…"
                  aria-label="Search indicators by title or description"
                  className="w-full rounded-md border border-grid-700 bg-grid-900 px-3 py-2 text-sm text-grid-100 placeholder:text-grid-400 focus:border-grid-500 focus:outline-none sm:max-w-xs"
                />
                <select
                  value={riskFilter}
                  onChange={(event: ChangeEvent<HTMLSelectElement>) => setRiskFilter(event.target.value as RiskFilter)}
                  aria-label="Filter indicators by risk level"
                  className="w-full rounded-md border border-grid-700 bg-grid-900 px-3 py-2 text-sm text-grid-100 focus:border-grid-500 focus:outline-none sm:w-auto"
                >
                  {RISK_FILTER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <p className="whitespace-nowrap text-xs text-grid-300">
                {filteredData.length} of {data.length} indicator{data.length === 1 ? "" : "s"} · last synced{" "}
                {new Date(dataUpdatedAt).toLocaleTimeString()}
              </p>
            </div>

            {filteredData.length === 0 ? (
              <NoFilterMatchesNotice totalCount={data.length} />
            ) : (
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
                    {filteredData.map((indicator) => {
                      // Null-safe, tag-stripped, still rendered as plain JSX
                      // text below -- never passed to dangerouslySetInnerHTML.
                      const cleansedDescription = stripHtmlTags(indicator.description);
                      return (
                      <tr
                        key={indicator.id}
                        className="align-top transition-colors hover:bg-grid-800/60"
                      >
                        <td className="px-4 py-3 font-mono text-grid-100 whitespace-nowrap">
                          {indicator.title}
                        </td>
                        <td
                          className="max-w-xs truncate px-4 py-3 text-grid-300"
                          title={cleansedDescription}
                        >
                          {cleansedDescription}
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
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
