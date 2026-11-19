// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { describe, expect, it } from "vitest";

import { EN_US_TIME_RANGE_PACK, parseTimeRangeInput } from "../index";
import type { ParseContext, RangeLimits, TimeRangeParseResult } from "../types";
import { baseContext, isoUs } from "./helpers";

const NOW = "2026-11-17T12:00:00Z";
const H = 3_600_000_000;
const now = isoUs(NOW);

function parse(
  text: string,
  limits: Partial<RangeLimits> = {},
  extra: Partial<ParseContext> = {},
): TimeRangeParseResult {
  const ctx = baseContext(EN_US_TIME_RANGE_PACK, text, NOW, "Europe/Berlin");
  return parseTimeRangeInput({ ...ctx, ...extra, limits: { allowFuture: false, ...limits } });
}

describe("policy", () => {
  it("blocks a wholly future range with no fix", () => {
    const r = parse("tomorrow");
    expect(r.state === "blocked" && r.reason).toBe("future");
    expect(r.state === "blocked" && r.fix).toBeUndefined();
  });

  it("clamps an end within the skew to now and blocks beyond it", () => {
    const within = parse(`2026-11-17T12:50:00+01:00 to 2026-11-17T13:00:03+01:00`);
    expect(within.state === "valid" && within.reading.endUs).toBe(now);
    const beyond = parse(`2026-11-17T12:50:00+01:00 to 2026-11-17T13:30:00+01:00`);
    expect(beyond.state === "blocked" && beyond.reason).toBe("future");
    expect(
      beyond.state === "blocked" && beyond.fix && [beyond.fix.startUs, beyond.fix.endUs],
    ).toEqual([isoUs("2026-11-17T12:50:00+01:00"), now]);
  });

  it("clips a date-only end to now", () => {
    const r = parse("2026-11-16 to 2026-11-18");
    expect(r.state === "valid" && r.reading.endUs).toBe(now);
  });

  it("enforces maxEndUs in the past whatever allowFuture says", () => {
    const maxEndUs = now - 24 * H;
    for (const allowFuture of [false, true]) {
      const r = parse("last 2 hours", { maxEndUs, allowFuture });
      expect(r.state === "blocked" && r.reason, String(allowFuture)).toBe("after-max");
    }
  });

  it("reports future before after-max when both fail", () => {
    const r = parse("2026-11-17T12:00:00+01:00 to 2026-11-17T14:00:00+01:00", {
      maxEndUs: now - H,
    });
    expect(r.state === "blocked" && r.reason).toBe("future");
  });

  it("blocks before-min and max-span, each with a revalidated fix", () => {
    const min = parse("last 3 days", { minStartUs: now - 24 * H });
    expect(min.state === "blocked" && min.reason).toBe("before-min");
    expect(min.state === "blocked" && min.fix && min.fix.startUs).toBe(now - 24 * H);
    const span = parse("last 3 days", { maxSpanUs: 2 * H });
    expect(span.state === "blocked" && span.reason).toBe("max-span");
    expect(span.state === "blocked" && span.fix && [span.fix.kind, span.fix.rolling]).toEqual([
      "rolling",
      { value: 2, unit: "h" },
    ]);
  });

  it("drops the fix of a future range that also breaks the span cap when the clamp fails", () => {
    const r = parse("2030-01-01 to 2030-01-02", { maxSpanUs: H });
    expect(r.state === "blocked" && r.reason).toBe("future");
    expect(r.state === "blocked" && r.fix).toBeUndefined();
  });

  it("gives an absolute fix fixed to now for a non-rolling source", () => {
    const r = parse("2026-11-10 to 2026-11-18", { maxSpanUs: 2 * H });
    expect(
      r.state === "blocked" && r.fix && [r.fix.kind, r.fix.fixedToNow, r.fix.calendarToken],
    ).toEqual(["absolute", true, undefined]);
  });

  it("blocks a range wholly before retention and notes a partial overlap", () => {
    const floor = now - 48 * H;
    const before = parse("2026-11-10", { retentionStartUs: floor });
    expect(before.state === "blocked" && before.reason).toBe("retention");
    const partial = parse("last 3 days", { retentionStartUs: floor });
    expect(partial.state === "valid" && partial.reading.notes).toContainEqual({
      kind: "partial-retention",
      keptFromUs: floor,
    });
    expect(parse("1969-12-31").state === "blocked").toBe(true);
  });

  it("keeps an ambiguity when one reading breaks a limit, and blocks it when all do", () => {
    const one = parse("15M", { maxSpanUs: 7 * 24 * H });
    expect(one.state).toBe("ambiguous");
    expect(one.state === "ambiguous" && one.readings.map((r) => r.blocked)).toEqual([
      undefined,
      "max-span",
    ]);
    const all = parse("15M", { maxSpanUs: 60_000_000 });
    expect(all.state).toBe("blocked");
    expect(all.state === "blocked" && all.others?.length).toBe(1);
  });

  it("returns invalid/zero-length for a range that starts where it ends", () => {
    const r = parse("09:00 to 09:00");
    expect(r.state === "invalid" && r.reason).toBe("zero-length");
  });

  it.each([
    ["since now", [0, 9]],
    ["now+3s", [0, 6]],
    ["?from=now&to=now", [0, 16]],
  ])(
    "returns invalid/zero-length spanning the whole input for %s, which starts at or after its clipped end",
    (text, span) => {
      const r = parse(text);
      expect(r.state === "invalid" && r.reason, JSON.stringify(r)).toBe("zero-length");
      expect(r.state === "invalid" && r.examples.length).toBeGreaterThan(0);
      expect(r.state === "invalid" && r.at).toEqual(span);
    },
  );

  it("converts readings by kinds", () => {
    const rolling = parse(
      "last 2 hours",
      {},
      { kinds: { relative: false, calendar: true, absolute: true } },
    );
    expect(
      rolling.state === "valid" && [
        rolling.reading.kind,
        rolling.reading.fixedToNow,
        rolling.reading.rolling,
      ],
    ).toEqual(["absolute", true, undefined]);
    const calendar = parse(
      "yesterday",
      {},
      { kinds: { relative: true, calendar: false, absolute: true } },
    );
    expect(
      calendar.state === "valid" && [calendar.reading.kind, calendar.reading.calendarToken],
    ).toEqual(["absolute", undefined]);
  });

  it("has no conversion for kinds.absolute, which the bar always sets (ui-spec §4)", () => {
    const r = parse(
      "2026-11-16",
      {},
      { kinds: { relative: true, calendar: true, absolute: false } },
    );
    expect(r.state === "valid" && r.reading.kind).toBe("absolute");
  });

  it("offers a previous-day fix for a since-clock later than now (D3)", () => {
    const r = parse("since 22:00");
    expect(r.state === "blocked" && r.fix && [r.fix.startUs, r.fix.endUs]).toEqual([
      isoUs("2026-11-16T22:00:00+01:00"),
      now,
    ]);
  });
});
