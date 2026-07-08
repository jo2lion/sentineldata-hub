import { useMemo } from "react";
import type { CSSProperties } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import type { ThreatIndicator } from "../types/threat";
import type { SeverityTier } from "../lib/severity";
import {
  SEVERITY_TIERS,
  classifySeverityTier,
  SEVERITY_TIER_CHART_COLOR,
  SEVERITY_TIER_TEXT_CLASS,
} from "../lib/severity";

// --------------------------------------------------------------------------- #
// Threat Analytics -- Threat Velocity (cumulative time series) + Risk
// Composition (severity donut). Purely a client-side derived view over
// useThreats()'s existing `data`, passed in here as `indicators` -- no new
// network request, no new query key, same pattern CveMetricsGrid (App.tsx)
// already established.
//
// DATAVIZ SKILL DEVIATION FROM THE LITERAL TICKET, disclosed rather than
// silently applied: the ticket asked for the Threat Velocity line/area to
// use "our JIT green/amber colors" (plural, on one series). Per this
// project's dataviz skill -- anti-patterns.md: "Status color used for a
// non-status series"; color-formula.md: a lone series takes exactly ONE
// hue (sequential, or 1 categorical), never a second decorative hue -- a
// running-total COUNT is a magnitude, not a good/bad status signal, so it
// doesn't get two status-reserved hues layered onto one line for visual
// effect. This chart uses signal-ok (green) alone: a 2px stroke at full
// opacity plus a ~10% opacity area wash, matching this project's fixed
// area-fill mark spec exactly. No amber anywhere on this chart.
// --------------------------------------------------------------------------- #

type VelocityPoint = {
  dateLabel: string;
  sortKey: string;
  cumulativeCount: number;
};

function buildVelocitySeries(indicators: ThreatIndicator[]): VelocityPoint[] {
  // Bucketed by BROWSER-LOCAL calendar day (getFullYear/getMonth/getDate),
  // matching CveMetricsGrid's own already-disclosed browser-local
  // convention for this same observed_at field -- consistency with what's
  // already on this page, not a fresh decision made here. Unparseable
  // observed_at values (NaN from an Invalid Date) are excluded entirely,
  // same reasoning as CveMetricsGrid: ThreatIndicator.observed_at is
  // required and validated server-side, so this guards a future write path
  // bypassing that, not an expected case today.
  const countsByDay = new Map<string, { sortKey: string; label: string; count: number }>();

  for (const indicator of indicators) {
    const observed = new Date(indicator.observed_at);
    const year = observed.getFullYear();
    if (Number.isNaN(year)) continue;

    const month = observed.getMonth();
    const day = observed.getDate();
    const sortKey = `${year}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;

    const existing = countsByDay.get(sortKey);
    if (existing) {
      existing.count += 1;
    } else {
      countsByDay.set(sortKey, {
        sortKey,
        label: observed.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        count: 1,
      });
    }
  }

  // "Running total" per the ticket's own wording -- a cumulative sum across
  // days, not a raw per-day frequency. Only days that actually have at
  // least one indicator become a point; gaps between them are NOT
  // zero-filled. A genuinely empty calendar day contributes nothing to
  // change the cumulative total anyway, and this dataset can span years --
  // filling every calendar day in range could mean thousands of
  // zero-delta points for a sparse or long-lived feed history. Flagged,
  // not solved: a very sparse series will show a long straight
  // interpolated segment between far-apart days rather than a visually
  // "stepped" plateau -- acceptable for a monotone trend line, called out
  // rather than silently decided.
  const sortedDays = Array.from(countsByDay.values()).sort((a, b) =>
    a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0
  );

  let runningTotal = 0;
  return sortedDays.map((day) => {
    runningTotal += day.count;
    return { dateLabel: day.label, sortKey: day.sortKey, cumulativeCount: runningTotal };
  });
}

type SeveritySlice = {
  tier: SeverityTier;
  count: number;
};

function buildSeverityComposition(indicators: ThreatIndicator[]): SeveritySlice[] {
  const counts: Record<SeverityTier, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const indicator of indicators) {
    counts[classifySeverityTier(indicator.risk_score)] += 1;
  }
  // Zero-count tiers are dropped rather than rendered as an empty wedge --
  // an empty slice with a label and legend entry for "0 Low-severity
  // threats" is noise, not information, when every threat this cycle
  // happens to be Critical/High only.
  return SEVERITY_TIERS.map((tier) => ({ tier, count: counts[tier] })).filter(
    (slice) => slice.count > 0
  );
}

function ChartCardSkeleton({ title }: { title: string }) {
  // Mirrors App.tsx's KpiCardSkeleton animate-pulse pattern for visual
  // consistency. This is the INITIAL-load skeleton only -- see
  // ThreatAnalytics's own isLoading-vs-isFetching comment below for why it
  // must never reappear on a background refetch.
  return (
    <div className="rounded-lg border border-grid-800 bg-grid-900 px-4 py-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">{title}</p>
      <div className="mt-4 h-64 w-full animate-pulse rounded bg-grid-800/60" />
    </div>
  );
}

function ChartCardEmpty({ title, message }: { title: string; message: string }) {
  return (
    <div className="rounded-lg border border-grid-800 bg-grid-900 px-4 py-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">{title}</p>
      <p className="mt-4 flex h-64 items-center justify-center text-center text-sm text-grid-400">
        {message}
      </p>
    </div>
  );
}

// Shared recharts Tooltip styling -- literal CSS values (var(--color-...)),
// not Tailwind classes: recharts renders its own tooltip DOM outside of
// this file's JSX tree, so a className never reaches it. See
// lib/severity.ts's SEVERITY_TIER_CHART_COLOR comment for why var(...)
// still resolves correctly here regardless.
const TOOLTIP_CONTENT_STYLE: CSSProperties = {
  backgroundColor: "var(--color-grid-900)",
  border: "1px solid var(--color-grid-800)",
  borderRadius: "0.5rem",
  fontSize: "0.75rem",
  padding: "0.5rem 0.75rem",
};
const TOOLTIP_LABEL_STYLE: CSSProperties = { color: "var(--color-grid-300)" };
const TOOLTIP_ITEM_STYLE: CSSProperties = { color: "var(--color-grid-100)" };

function ThreatVelocityChart({ indicators }: { indicators: ThreatIndicator[] }) {
  const series = useMemo(() => buildVelocitySeries(indicators), [indicators]);

  if (series.length === 0) {
    return <ChartCardEmpty title="Threat Velocity" message="No dated indicators to plot yet." />;
  }

  return (
    <div className="rounded-lg border border-grid-800 bg-grid-900 px-4 py-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">
        Threat Velocity
      </p>
      <p className="mb-2 text-xs text-grid-400">Running total of ingested indicators over time</p>
      {/* Height includes room for the x-axis tick band, not just the plot
          area -- a fixed height that excludes it forces a nested scrollbar
          inside the card. */}
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            {/* Solid hairline grid, one step off the grid-900 card surface
                (grid-800) -- never dashed; dashing reads as a threshold or
                projection line, not a plain grid. */}
            <CartesianGrid stroke="var(--color-grid-800)" vertical={false} />
            <XAxis
              dataKey="dateLabel"
              tick={{ fill: "var(--color-grid-300)", fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: "var(--color-grid-800)" }}
              minTickGap={24}
            />
            <YAxis
              tick={{ fill: "var(--color-grid-300)", fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: "var(--color-grid-800)" }}
              allowDecimals={false}
              width={40}
            />
            <Tooltip
              contentStyle={TOOLTIP_CONTENT_STYLE}
              labelStyle={TOOLTIP_LABEL_STYLE}
              itemStyle={TOOLTIP_ITEM_STYLE}
              cursor={{ stroke: "var(--color-grid-700)", strokeWidth: 1 }}
            />
            {/* Single series -> no legend box (marks-and-anatomy.md: "a
                single series needs no legend box" -- the card title above
                already names what's plotted). */}
            <Area
              type="monotone"
              dataKey="cumulativeCount"
              name="Cumulative indicators"
              stroke="var(--color-signal-ok)"
              strokeWidth={2}
              fill="var(--color-signal-ok)"
              fillOpacity={0.1}
              dot={false}
              activeDot={{ r: 5 }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- #
// Click-to-filter cross-filtering (this pass)
//
// selectedSeverity/onSeverityClick are threaded down from App.tsx's global
// filter state -- this component does not own that state, only reports
// clicks upward and reflects the current selection back visually. Clicking
// the SAME slice twice is a toggle (App.tsx's handler clears the selection
// on a repeat click of the active tier), so there is always a way to
// deselect a slice without reaching for the separate "Clear Active
// Filters" control.
//
// Dimming, not recoloring: per this project's dataviz anti-patterns
// ("recolor-on-filter" -- a survivor's hue must never change when a
// selection/filter is applied), the non-selected slices keep their EXACT
// SEVERITY_TIER_CHART_COLOR hue and are only dimmed via fillOpacity. The
// selected slice gets a full-opacity fill plus a light stroke ring for
// emphasis -- this is the "highlight one, gray the rest" pattern the
// anti-patterns doc explicitly endorses over inventing a new color for
// the active state.
//
// Mouse-only, flagged not fixed: recharts' Pie/Cell sectors are SVG paths
// with no native tab-stop or keydown handling in this hand-authored stub's
// (and, to my knowledge, recharts' own) API surface. Unlike CveMetricsGrid's
// plain HTML <tr> rows (which get a real role="button"/tabIndex/onKeyDown
// treatment below in App.tsx), this donut's click-to-filter is mouse/touch
// only today. A keyboard-reachable equivalent -- e.g. rendering the legend
// entries as real <button> elements instead of recharts' own SVG legend --
// is a real accessibility gap, not addressed in this pass.
// --------------------------------------------------------------------------- #

function RiskCompositionChart({
  indicators,
  selectedSeverity,
  onSeverityClick,
}: {
  indicators: ThreatIndicator[];
  selectedSeverity: SeverityTier | null;
  onSeverityClick: (severity: SeverityTier) => void;
}) {
  const slices = useMemo(() => buildSeverityComposition(indicators), [indicators]);
  const total = indicators.length;

  if (slices.length === 0) {
    return <ChartCardEmpty title="Risk Composition" message="No indicators to classify yet." />;
  }

  return (
    <div className="rounded-lg border border-grid-800 bg-grid-900 px-4 py-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-grid-300">
        Risk Composition
      </p>
      <p className="mb-2 text-xs text-grid-400">
        {total} indicator{total === 1 ? "" : "s"} by severity tier
        {selectedSeverity !== null && (
          <>
            {" "}
            ·{" "}
            <span className={SEVERITY_TIER_TEXT_CLASS[selectedSeverity]}>
              filtering to {selectedSeverity}
            </span>
          </>
        )}
      </p>
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              contentStyle={TOOLTIP_CONTENT_STYLE}
              labelStyle={TOOLTIP_LABEL_STYLE}
              itemStyle={TOOLTIP_ITEM_STYLE}
            />
            {/* 4 categories -> a legend is mandatory (marks-and-anatomy.md:
                "a legend is always present for two or more series"). No
                per-slice inline labels -- with the Low tier sometimes a
                thin sliver, an inline label risks clipping; the legend +
                tooltip carry every value without that risk. */}
            <Legend
              iconType="circle"
              wrapperStyle={{ fontSize: "0.75rem", color: "var(--color-grid-300)" }}
            />
            <Pie
              data={slices}
              dataKey="count"
              nameKey="tier"
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="80%"
              paddingAngle={2}
              isAnimationActive={false}
            >
              {slices.map((slice) => {
                const isSelected = selectedSeverity === slice.tier;
                const isDimmed = selectedSeverity !== null && !isSelected;
                return (
                  <Cell
                    key={slice.tier}
                    fill={SEVERITY_TIER_CHART_COLOR[slice.tier]}
                    fillOpacity={isDimmed ? 0.35 : 1}
                    stroke={isSelected ? "var(--color-grid-100)" : undefined}
                    strokeWidth={isSelected ? 2 : 0}
                    cursor="pointer"
                    onClick={() => onSeverityClick(slice.tier)}
                  />
                );
              })}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function ThreatAnalytics({
  indicators,
  isLoading,
  selectedSeverity,
  onSeverityClick,
}: {
  indicators: ThreatIndicator[] | undefined;
  isLoading: boolean;
  selectedSeverity: SeverityTier | null;
  onSeverityClick: (severity: SeverityTier) => void;
}) {
  // Gated on isLoading, NOT isFetching -- deliberately. isLoading is
  // TanStack Query's "no cached data yet" state (true only on the very
  // first fetch); isFetching also flips true on every background 30s
  // refetch useThreats() already runs (see App.tsx). Gating the skeleton on
  // isFetching would re-flash it on every refetch even once real data
  // exists -- this project's dataviz conventions explicitly rule that out
  // ("refetch keeps the frame... no skeleton, no layout jump, no flash"):
  // once initial data is in, a background refetch should just re-render
  // these same charts with fresh numbers, not blank them out and back
  // every 30 seconds.
  if (isLoading) {
    return (
      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartCardSkeleton title="Threat Velocity" />
        <ChartCardSkeleton title="Risk Composition" />
      </div>
    );
  }

  // Null-safe by construction: `indicators` can still be undefined here in
  // principle (isError with no prior cached data) even though isLoading is
  // false -- both chart components receive a real array either way, never
  // having to null-check `indicators` internally themselves.
  const safeIndicators = indicators ?? [];

  return (
    <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ThreatVelocityChart indicators={safeIndicators} />
      <RiskCompositionChart
        indicators={safeIndicators}
        selectedSeverity={selectedSeverity}
        onSeverityClick={onSeverityClick}
      />
    </div>
  );
}

export default ThreatAnalytics;
