import { useMemo, useState } from "react";
import type { ChangeEvent, KeyboardEvent, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import type { DashboardMetrics, ThreatIndicator } from "./types/threat";
import type { SeverityTier } from "./lib/severity";
import { SEVERITY_TIERS, classifySeverityTier, SEVERITY_TIER_TEXT_CLASS } from "./lib/severity";
import { ThreatAnalytics } from "./components/ThreatAnalytics";

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

// --------------------------------------------------------------------------- #
// Connection status dot -- inline inside StatusPill, not a separate component.
//
// A prior pass extracted this into a standalone LiveStatusDot component
// rendered next to StatusPill. This ticket explicitly removes that: the dot
// goes back to being the literal <span> StatusPill always rendered in this
// exact spot, just now state-driven instead of a flat bg-current. One
// element, one component boundary -- not two.
//
// bg-green-500/400, bg-yellow-500/400, and bg-red-500 are Tailwind's built-in
// default-palette colors, not this project's custom signal-*/grid-* tokens --
// deliberately so, same reasoning as the prior pass: index.css only contains
// `@import "tailwindcss";` with no @theme block defining --color-signal-* /
// --color-grid-* anywhere, and main.tsx imports a separate, already-stale
// ./styles/output.css instead of index.css. That is a real, separate,
// still-unresolved finding -- not fixed here, out of this ticket's scope --
// and stock Tailwind palette colors sidestep it entirely since they need no
// @theme customization to resolve.
//
// isFetching alone is sufficient for the amber/syncing branch even though
// this ticket's spec calls out "isFetching or isLoading": TanStack Query's
// isLoading (no cached data yet) is a strict subset of isFetching (any fetch
// in flight, including background refetches on the existing 30s
// refetchInterval) -- isLoading true always implies isFetching true. The
// condition below is still written as the literal isFetching (not simplified
// further), so it reads the same as the ticket's stated logic rather than
// silently depending on readers already knowing that subset relationship.
//
// No new timer, no local useEffect polling loop: this is still driven
// entirely by useThreats()'s existing TanStack Query state in App(), which
// already owns connection-health polling safely (bounded retries, requests
// cancelled on unmount). That's what guarantees no runaway "state processing
// loop" here, same as the prior pass.
//
// Known, deliberately NOT fixed here: StatusPill's tone/label text (the
// "Connection Fault" / "Syncing" / "Live" string and its signal-* color) is
// still driven by isLoading alone, unchanged from before this ticket. During
// a background refetch (isFetching true, isLoading false, isError false) the
// dot will pulse amber while the label still reads "Live" -- a real,
// momentary dot/label disagreement. This ticket only asked to wire the dot's
// conditional styling to isError/isFetching, not to rework the label logic;
// changing that is a separate, unscoped decision, flagged here rather than
// silently left inconsistent or silently "fixed" beyond what was asked.
// --------------------------------------------------------------------------- #

function StatusPill({
  tone,
  label,
  isError,
  isFetching,
}: {
  tone: PillTone;
  label: string;
  isError: boolean;
  isFetching: boolean;
}) {
  const toneClass: Record<PillTone, string> = {
    ok: "bg-signal-ok/15 text-signal-ok border-signal-ok/40",
    warning: "bg-signal-warning/15 text-signal-warning border-signal-warning/40",
    critical: "bg-signal-critical/15 text-signal-critical border-signal-critical/40",
    muted: "bg-signal-muted/15 text-signal-muted border-signal-muted/40",
  };

  let dot: ReactNode;
  if (isError) {
    // Flat, static failure signal -- zero animation, by explicit ticket
    // requirement. A pulsing dot for a dropped connection reads as "still
    // happening"; a solid one reads as "stopped," the correct signal here.
    dot = <span className="h-1.5 w-1.5 rounded-full bg-red-500" />;
  } else if (isFetching) {
    dot = (
      <span className="relative inline-flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-yellow-400 opacity-75" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-yellow-500" />
      </span>
    );
  } else {
    dot = (
      <span className="relative inline-flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-green-500" />
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${toneClass[tone]}`}
    >
      {dot}
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

// --------------------------------------------------------------------------- #
// CVE Year x Severity cross-tabulation grid
//
// Purely a client-side derived view over useThreats()'s existing `data`
// array -- no new network request, no new query key. Aggregation is
// memoized inside this component (not lifted into App()'s own useMemo)
// since it depends only on the `indicators` prop, keeping the memoization
// colocated with the data it derives from.
//
// Severity tiers mirror riskTone()'s exact thresholds above (5.0 / 4.0 /
// 3.0) -- duplicated here, not shared, because riskTone returns a Tailwind
// class string for a single row's text color, while this needs a bucket
// LABEL to cross-tabulate an entire array; forcing one to call the other
// would mean either parsing a class string back into a tier name (fragile)
// or making riskTone depend on a tier enum it has no other reason to know
// about. This is now the THIRD call site sharing these exact three cutoffs
// (riskTone, matchesRiskFilter's 3-bucket variant, and this one) -- a real,
// flagged duplication risk: if backend/app/data/pipeline.py's
// _process_batch risk tiers ever change, all three need to change together,
// and nothing enforces that today. Not unified into one shared source of
// truth in this pass -- out of this ticket's scope, and touching
// riskTone/matchesRiskFilter risks regressing two already-working,
// differently-shaped call sites for a ticket that didn't ask for that.
//
// Year is read from `observed_at` (ISO 8601 UTC string per
// pipeline.py's UTCDateTime + ThreatIndicator's own aware-only validator)
// via `new Date(...).getFullYear()` -- browser-LOCAL year, not UTC year.
// This mirrors every other Date rendering already in this file (the
// table's Observed At column and MetricsPanel's "Last DB write" line both
// already call .toLocaleString() on a `new Date(...)`, i.e. already
// browser-local), so this grid stays consistent with what the rest of the
// page already shows the viewer -- at the cost of the well-known caveat
// that a threat observed at 2025-12-31T23:30:00Z would bucket under 2026
// for a viewer in a positive UTC offset. Flagged, not solved: fixing it
// means deciding whether the WHOLE page should switch to UTC-year display,
// not just this grid, which is out of this ticket's scope.
//
// Malformed/unparseable observed_at values (`new Date(...)` producing an
// Invalid Date, whose .getFullYear() is NaN) are excluded from the tally
// entirely rather than surfacing as a "NaN" row or silently miscounted
// under year 0 -- ThreatIndicator.observed_at is a required, validated
// field server-side, so this should not happen in practice, but the grid
// must not crash or render garbage if a future write path ever bypasses
// that validation.
// --------------------------------------------------------------------------- #

// SeverityTier / SEVERITY_TIERS / classifySeverityTier / SEVERITY_TIER_TEXT_CLASS
// now live in ./lib/severity.ts, not here -- extracted this pass because
// ThreatAnalytics.tsx's Risk Composition donut became a third consumer of
// the exact same classification. See that module's own doc comment for why
// riskTone/matchesRiskFilter below are deliberately NOT also routed through
// it.

type YearSeverityRow = {
  year: number;
  counts: Record<SeverityTier, number>;
  total: number;
};

function aggregateByYearAndSeverity(indicators: ThreatIndicator[]): YearSeverityRow[] {
  const rowsByYear = new Map<number, Record<SeverityTier, number>>();

  for (const indicator of indicators) {
    const year = new Date(indicator.observed_at).getFullYear();
    if (Number.isNaN(year)) continue; // see module comment above

    let counts = rowsByYear.get(year);
    if (!counts) {
      counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      rowsByYear.set(year, counts);
    }
    counts[classifySeverityTier(indicator.risk_score)] += 1;
  }

  return Array.from(rowsByYear.entries())
    .map(([year, counts]) => ({
      year,
      counts,
      total: counts.Critical + counts.High + counts.Medium + counts.Low,
    }))
    .sort((a, b) => b.year - a.year); // most recent year first
}

function CveMetricsGrid({
  indicators,
  selectedYear,
  onYearClick,
}: {
  indicators: ThreatIndicator[] | undefined;
  selectedYear: number | null;
  onYearClick: (year: number) => void;
}) {
  // Null-safe by construction: `indicators` is undefined during the
  // pre-first-response window (React Query has no cached data yet) and
  // during the isError path -- aggregateByYearAndSeverity always receives
  // a real array (falling back to []) so it never has to null-check
  // internally, and the zero-row branch below covers both "no data yet"
  // and "data loaded but genuinely empty" with the same message, since
  // from this component's perspective they are the same "nothing to
  // cross-tabulate yet" state.
  const rows = useMemo(() => aggregateByYearAndSeverity(indicators ?? []), [indicators]);

  return (
    <div className="mb-6 overflow-hidden rounded-lg border border-grid-800 bg-grid-900">
      <div className="border-b border-grid-800 px-4 py-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-grid-300">
          CVE Volume by Year &amp; Severity
        </h2>
      </div>

      {rows.length === 0 ? (
        <p className="px-4 py-6 text-center text-sm text-grid-400">
          No dated indicators to aggregate yet.
        </p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="bg-grid-900 text-grid-300">
            <tr>
              <th className="px-4 py-2 font-medium">Year</th>
              {SEVERITY_TIERS.map((tier) => (
                <th
                  key={tier}
                  className={`px-4 py-2 text-right font-medium ${SEVERITY_TIER_TEXT_CLASS[tier]}`}
                >
                  {tier}
                </th>
              ))}
              <th className="px-4 py-2 text-right font-medium text-grid-100">Total</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-grid-800">
            {rows.map((row) => {
              // Click-to-filter cross-filtering (this pass): a row sets
              // App.tsx's global selectedYear -- clicking the ALREADY
              // selected year toggles it back off (see App's
              // handleYearSelect), so there's always a way to deselect a
              // row without reaching for "Clear Active Filters".
              //
              // Highlight is applied via a background wash on the <tr>
              // (background-color on a table row DOES render in every
              // modern browser) plus a left accent border on the leading
              // <td> specifically -- NOT a border on the <tr> itself.
              // Borders on <tr> elements are unreliable across browsers
              // under the default `border-collapse: separate` table model
              // (many engines simply never paint them), so the accent
              // lives on the cell, where border painting is guaranteed.
              const isSelected = selectedYear === row.year;
              return (
                <tr
                  key={row.year}
                  role="button"
                  tabIndex={0}
                  aria-pressed={isSelected}
                  onClick={() => onYearClick(row.year)}
                  onKeyDown={(event: KeyboardEvent<HTMLTableRowElement>) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onYearClick(row.year);
                    }
                  }}
                  className={`cursor-pointer transition-colors hover:bg-grid-800/60 ${
                    isSelected ? "bg-signal-ok/5" : ""
                  }`}
                >
                  <td
                    className={`px-4 py-2 font-mono text-grid-100 ${
                      isSelected ? "border-l-2 border-signal-ok pl-3" : ""
                    }`}
                  >
                    {row.year}
                  </td>
                  {SEVERITY_TIERS.map((tier) => (
                    <td
                      key={tier}
                      className={`px-4 py-2 text-right font-mono ${SEVERITY_TIER_TEXT_CLASS[tier]}`}
                    >
                      {row.counts[tier]}
                    </td>
                  ))}
                  <td className="px-4 py-2 text-right font-mono font-semibold text-grid-100">
                    {row.total}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function App() {
  const { data, isLoading, isFetching, isError, error, dataUpdatedAt } = useThreats();

  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");

  // --------------------------------------------------------------------- #
  // Global cross-filter state (this pass): selectedYear / selectedSeverity
  // are set by clicking a CveMetricsGrid row or a ThreatAnalytics donut
  // sector respectively, and scope the main feed table below (see
  // filteredData). Typed as `SeverityTier | null` here, not the ticket's
  // literal `string | null` -- the value assigned is always one of exactly
  // four known tier strings (never an arbitrary string), and every place
  // that reads it (matching against classifySeverityTier's return type,
  // indexing SEVERITY_TIER_TEXT_CLASS/SEVERITY_TIER_CHART_COLOR) already
  // requires that exact union. A plain `string | null` would still satisfy
  // every current call site but would also silently accept a typo'd tier
  // name with zero compiler help -- the narrower type is strictly safer at
  // no cost, same reasoning as prior tickets' UTC-vs-naive datetime calls.
  //
  // These are independent, orthogonal filters (a year selection does not
  // require a severity selection, and vice versa), combined with logical
  // AND in filteredData below alongside the pre-existing search/riskFilter
  // dimensions -- FOUR filter dimensions can now be active simultaneously
  // on the same list.
  //
  // Deliberately NOT re-applied to CveMetricsGrid's or ThreatAnalytics's
  // own aggregations: selecting a year does not re-slice the severity
  // donut to that year, and selecting a severity does not re-slice the
  // year table to that tier. Both charts always aggregate the FULL
  // (unfiltered) `data` array; only the feed list below narrows. This is
  // a real, deliberate scope decision, not an oversight -- true two-way
  // cross-filtering (each chart re-aggregating against the other's
  // selection) is a legitimate pattern this project's own dataviz
  // conventions would generally prefer ("all charts re-render against the
  // same slice, so the numbers always agree"), but it introduces a real
  // consistency question this ticket doesn't resolve: if selecting the
  // Critical slice removed all non-Critical wedges from the donut itself,
  // there would be nothing left to click to get back to High/Medium/Low
  // without the separate Clear button. Keeping the charts as stable,
  // always-full-context "selectors" and only slicing the list below
  // sidesteps that, at the cost of the donut/grid never visually
  // reflecting the OTHER filter dimension. Flagged, not silently decided.
  const [selectedYear, setSelectedYear] = useState<number | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<SeverityTier | null>(null);

  // Toggle semantics: clicking the currently-active selection clears it,
  // matching the same "click again to deselect" affordance already given
  // to CveMetricsGrid's rows and ThreatAnalytics' donut sectors visually
  // (both re-render as "selected" only while their value === state).
  const handleYearSelect = (year: number) => {
    setSelectedYear((previous) => (previous === year ? null : year));
  };
  const handleSeveritySelect = (severity: SeverityTier) => {
    setSelectedSeverity((previous) => (previous === severity ? null : severity));
  };
  const clearActiveFilters = () => {
    setSelectedYear(null);
    setSelectedSeverity(null);
  };

  // Derived, not stored -- filteredData is always a pure function of
  // (data, searchQuery, riskFilter, selectedYear, selectedSeverity).
  // useMemo avoids recomputing the filter pass on unrelated re-renders
  // (e.g. the metrics query refetching).
  const filteredData = useMemo(() => {
    if (!data) return [];
    const normalizedQuery = searchQuery.trim().toLowerCase();
    return data.filter((indicator) => {
      if (!matchesRiskFilter(indicator.risk_score, riskFilter)) return false;
      // selectedSeverity uses the SAME 4-tier classifySeverityTier as the
      // CveMetricsGrid/ThreatAnalytics aggregations it was clicked from --
      // NOT riskFilter's separate 3-bucket scheme above. Both can be
      // active at once (e.g. riskFilter="warning" AND
      // selectedSeverity="Medium"), in which case they simply AND
      // together; that can legitimately narrow the list to zero rows
      // (handled by NoFilterMatchesNotice below) rather than being
      // treated as a conflict to resolve.
      if (selectedSeverity !== null && classifySeverityTier(indicator.risk_score) !== selectedSeverity) {
        return false;
      }
      if (selectedYear !== null && new Date(indicator.observed_at).getFullYear() !== selectedYear) {
        return false;
      }
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
  }, [data, searchQuery, riskFilter, selectedSeverity, selectedYear]);

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
            isError={isError}
            isFetching={isFetching}
          />
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        <MetricsPanel />

        <CveMetricsGrid indicators={data} selectedYear={selectedYear} onYearClick={handleYearSelect} />

        <ThreatAnalytics
          indicators={data}
          isLoading={isLoading}
          selectedSeverity={selectedSeverity}
          onSeverityClick={handleSeveritySelect}
        />

        {(selectedYear !== null || selectedSeverity !== null) && (
          <div className="mb-6 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-signal-ok/30 bg-signal-ok/5 px-4 py-2">
            <p className="text-xs text-grid-100">
              Filtering to
              {selectedYear !== null && <span className="font-mono"> {selectedYear}</span>}
              {selectedYear !== null && selectedSeverity !== null && " ·"}
              {selectedSeverity !== null && (
                <span className={`font-semibold ${SEVERITY_TIER_TEXT_CLASS[selectedSeverity]}`}>
                  {" "}
                  {selectedSeverity}
                </span>
              )}
              . Clicking the same selection again also clears it.
            </p>
            <button
              type="button"
              onClick={clearActiveFilters}
              className="whitespace-nowrap rounded-md border border-grid-700 bg-grid-900 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-grid-100 transition-colors hover:border-signal-ok hover:text-signal-ok"
            >
              Clear Active Filters
            </button>
          </div>
        )}

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
