import { NextResponse } from "next/server";

export function gateUnavailableResponse(): NextResponse {
  return NextResponse.json({ error: "gate_unavailable" }, {
    status: 503,
    headers: { "Cache-Control": "no-store", "Retry-After": "5" },
  });
}
