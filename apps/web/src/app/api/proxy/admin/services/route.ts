/**
 * GET /api/proxy/admin/services - list all services / engagements (admin).
 * Forwards the include_archived query flag. Cross-tenant by design.
 */

import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { ApiError, apiFetch } from "@/lib/api";
import { authOptions } from "@/lib/auth/options";

export async function GET(request: Request): Promise<NextResponse> {
  const session = await getServerSession(authOptions);
  const bearer = session?.accessToken;
  if (!bearer) {
    return NextResponse.json(
      { error: { code: 401, message: "Not signed in." } },
      { status: 401 },
    );
  }
  const includeArchived =
    new URL(request.url).searchParams.get("include_archived") === "true";
  const path = includeArchived
    ? "/admin/services?include_archived=true"
    : "/admin/services";
  try {
    const result = await apiFetch<unknown>(path, { bearer, clientId: "" });
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(err.payload ?? { error: { code: err.status } }, {
        status: err.status,
      });
    }
    return NextResponse.json(
      { error: { message: "Upstream admin/services call failed." } },
      { status: 502 },
    );
  }
}
