
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(body: object, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: cors });
  }

  if (req.method !== "POST") {
    return respond({ error: "POST only" }, 405);
  }

  try {
    const auth = req.headers.get("Authorization");

    if (!auth?.startsWith("Bearer ")) {
      return respond({ error: "Unauthorized" }, 401);
    }

    const token = auth.slice(7);

    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const operatorEmail = Deno.env.get("QC_OPERATOR_EMAIL");

    if (!url || !anon || !service || !operatorEmail) {
      return respond({ error: "Backend secrets missing" }, 500);
    }

    const userClient = createClient(url, anon, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const admin = createClient(url, service, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    // Verify the user's token
    const { data, error } = await userClient.auth.getUser(token);

    if (error || !data.user) {
      return respond({ error: "Invalid session" }, 401);
    }

    const user = data.user;
    const body = await req.json().catch(() => ({}));
    const action = body.action;

    // Operator is verified server-side only
    const isOperator =
      user.email?.toLowerCase() === operatorEmail.toLowerCase();

    if (action === "check-role") {
      return respond({
        authenticated: true,
        username: user.email,
        isOperator,
      });
    }

    if (action === "signout-all") {
      const { error: signoutError } =
        await admin.auth.admin.signOut(token, "global");

      if (signoutError) {
        return respond({ error: signoutError.message }, 400);
      }

      return respond({ success: true });
    }

    // Operator-only future actions
    if (action.startsWith("operator-") && !isOperator) {
      return respond({ error: "Forbidden" }, 403);
    }

    return respond({ error: "Unknown action" }, 400);
  } catch {
    return respond({ error: "Internal server error" }, 500);
  }
});
