/**
 * GET  /api/proxy/admin/users - list all user accounts (admin).
 * POST /api/proxy/admin/users - create an admin or client user (admin).
 *
 * Admin-only; cross-tenant by design (does not forward X-Client-Id).
 */

import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { ApiError, apiFetch } from "@/lib/api";
import { authOptions } from "@/lib/auth/options";

export async function GET(): Promise<NextResponse> {
  const session = await getServerSession(authOptions);
  const bearer = session?.accessToken;
  if (!bearer) {
    return NextResponse.json(
      { error: { code: 401, message: "Not signed in." } },
      { status: 401 },
    );
  }
  try {
    const result = await apiFetch<unknown>("/admin/users", {
      bearer,
      clientId: "",
    });
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(err.payload ?? { error: { code: err.status } }, {
        status: err.status,
      });
    }
    return NextResponse.json(
      { error: { message: "Upstream admin/users call failed." } },
      { status: 502 },
    );
  }
}

export async function POST(request: Request): Promise<NextResponse> {
  const session = await getServerSession(authOptions);
  const bearer = session?.accessToken;
  if (!bearer) {
    return NextResponse.json(
      { error: { code: 401, message: "Not signed in." } },
      { status: 401 },
    );
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    body = undefined;
  }
  try {
    const result = await apiFetch<unknown>("/admin/users", {
      method: "POST",
      body: body as Record<string, unknown> | undefined,
      bearer,
      clientId: "",
    });
    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(err.payload ?? { error: { code: err.status } }, {
        status: err.status,
      });
    }
    return NextResponse.json(
      { error: { message: "Upstream admin/users call failed." } },
      { status: 502 },
    );
  }
}
