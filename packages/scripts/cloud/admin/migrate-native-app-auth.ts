/** One-time import of the protected deployment registry before database-only cutover. */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Client } from "pg";
import {
  readDatabaseIdentityConfig,
  runDatabaseIdentityPreflight,
} from "../../../cloud/scripts/admin/preflight-database-identity";
import { enforceTlsForRemote } from "../../../cloud/shared/src/db/client";
import { parseAndroidAssetLinksConfig } from "../../../cloud/shared/src/lib/auth/android-asset-links";
import { selectNativeAuthCallback } from "../../../cloud/shared/src/lib/auth/native-auth-callback-config";
import {
  parseRegisteredMobileClients,
  type RegisteredMobileClient,
} from "../../../cloud/shared/src/lib/services/mobile-client-registry";

type Row = Record<string, unknown>;
export interface MigrationDatabase {
  query(text: string, values?: unknown[]): Promise<{ rows: Row[] }>;
}
export interface NativeRegistrySource {
  primaryAppId?: string;
  clients?: string;
  assetLinks?: string;
  callbacks?: string;
}
function refuse(invariant: string): never {
  throw new Error(`Native client migration refused: ${invariant}`);
}
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const primary = {
  clientId: "ai.elizaos.app",
  redirectUri: "https://eliza.app/auth/callback",
};

export function nativeRegistrySnapshot(source: NativeRegistrySource) {
  if (
    !source.clients?.trim() ||
    !source.assetLinks?.trim() ||
    !source.callbacks?.trim()
  )
    refuse("complete_source_snapshot_required");
  if (source.primaryAppId && !UUID.test(source.primaryAppId))
    refuse("primary_identity");
  const parsed = parseRegisteredMobileClients(source.clients || "[]", {
    ...primary,
    appId: source.primaryAppId,
  });
  if (!parsed.ok) refuse("registry_invalid");
  const registrations: RegisteredMobileClient[] = [
    ...(source.primaryAppId
      ? [{ ...primary, appId: source.primaryAppId, enabled: true }]
      : []),
    ...parsed.registrations,
  ];
  if (!registrations.length) refuse("empty_registry");
  const assets = parseAndroidAssetLinksConfig(source.assetLinks);
  if (!assets.ok) refuse("asset_links_invalid");
  let callbacks: unknown;
  try {
    callbacks = JSON.parse(source.callbacks || "[]");
  } catch {
    refuse("callbacks_invalid");
  }
  if (!Array.isArray(callbacks)) refuse("callbacks_invalid");
  const records = registrations.map((entry) => {
    const callback = selectNativeAuthCallback(
      source.callbacks || "[]",
      new URL(entry.redirectUri),
    );
    const ownAssets = assets.statements.filter(
      (statement) => statement.target.package_name === entry.clientId,
    );
    if (ownAssets.length > 1) refuse("asset_links_ambiguous");
    return {
      client_id: entry.clientId,
      app_id: entry.appId.toLowerCase(),
      redirect_uri: entry.redirectUri,
      enabled: entry.enabled,
      credential_ttl_seconds: entry.credentialTtlSeconds ?? null,
      android_package_name: ownAssets[0]?.target.package_name ?? null,
      android_cert_fingerprints:
        ownAssets[0]?.target.sha256_cert_fingerprints ?? null,
      android_relations: ownAssets[0]?.relation ?? null,
      callback_android_package: callback?.androidPackage ?? null,
      browser_sign_in: callback?.browserSignIn ?? null,
    };
  });
  // Packages that changed independently of the stable client ID are joined by
  // the protected callback map, never inferred from an app name or an origin.
  for (const asset of assets.statements) {
    if (
      records.some(
        (record) => record.android_package_name === asset.target.package_name,
      )
    )
      continue;
    const candidates = records.filter(
      (record) =>
        record.callback_android_package === asset.target.package_name &&
        !record.android_package_name,
    );
    if (candidates.length !== 1) refuse("unmatched_asset_links");
    Object.assign(candidates[0], {
      android_package_name: asset.target.package_name,
      android_cert_fingerprints: asset.target.sha256_cert_fingerprints,
      android_relations: asset.relation,
    });
  }
  for (const callback of callbacks) {
    if (
      !callback ||
      typeof callback !== "object" ||
      !("redirectUri" in callback) ||
      !records.some((record) => record.redirect_uri === callback.redirectUri)
    )
      refuse("unmatched_callback");
  }
  return records.sort((left, right) =>
    left.client_id.localeCompare(right.client_id),
  );
}

/** Imports all records or none. Existing rows must match exactly; no overwrite path exists. */
export async function migrateNativeRegistry(
  database: MigrationDatabase,
  source: NativeRegistrySource,
  environment: "staging" | "production",
) {
  const snapshot = nativeRegistrySnapshot(source);
  await database.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
  try {
    await database.query("SELECT pg_advisory_xact_lock(39257)");
    {
      const sql = await readFile(
        new URL(
          "../../../cloud/shared/src/db/migrations/0574_native_app_auth_client_registration.sql",
          import.meta.url,
        ),
        "utf8",
      );
      for (const statement of sql.split("--> statement-breakpoint"))
        if (statement.trim()) await database.query(statement);
    }
    for (const record of snapshot) {
      const apps = record.enabled
        ? await database.query(
            "SELECT id, is_active, is_approved FROM apps WHERE allowed_origins @> $1::jsonb",
            [JSON.stringify([record.redirect_uri])],
          )
        : await database.query(
            "SELECT id, is_active, is_approved FROM apps WHERE id = $1::uuid",
            [record.app_id],
          );
      if (
        apps.rows.length !== 1 ||
        apps.rows[0]?.id !== record.app_id ||
        (record.enabled &&
          (apps.rows[0]?.is_active !== true ||
            apps.rows[0]?.is_approved !== true))
      )
        refuse("app_binding_not_unique_and_approved");
      await database.query(
        `INSERT INTO mobile_app_auth_clients
        (client_id,app_id,redirect_uri,enabled,credential_ttl_seconds,android_package_name,android_cert_fingerprints,android_relations,callback_android_package,browser_sign_in)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10::jsonb) ON CONFLICT(client_id) DO NOTHING`,
        [
          record.client_id,
          record.app_id,
          record.redirect_uri,
          record.enabled,
          record.credential_ttl_seconds,
          record.android_package_name,
          JSON.stringify(record.android_cert_fingerprints),
          JSON.stringify(record.android_relations),
          record.callback_android_package,
          JSON.stringify(record.browser_sign_in),
        ],
      );
      const found = await database.query(
        "SELECT client_id,app_id,redirect_uri,enabled,credential_ttl_seconds,android_package_name,android_cert_fingerprints,android_relations,callback_android_package,browser_sign_in FROM mobile_app_auth_clients WHERE client_id=$1",
        [record.client_id],
      );
      if (
        found.rows.length !== 1 ||
        JSON.stringify(found.rows[0]) !== JSON.stringify(record)
      ) {
        // JSONB key ordering is not semantic; compare each structured field canonically.
        const canonical = (value: unknown): string =>
          JSON.stringify(value, (_, item) =>
            item && typeof item === "object" && !Array.isArray(item)
              ? Object.fromEntries(
                  Object.entries(item).sort(([a], [b]) => a.localeCompare(b)),
                )
              : item,
          );
        if (
          found.rows.length !== 1 ||
          canonical(found.rows[0]) !== canonical(record)
        )
          refuse("existing_registration_conflict");
      }
    }
    const digest = createHash("sha256")
      .update(JSON.stringify(snapshot))
      .digest("hex");
    const prior = await database.query(
      "SELECT source_digest, client_count FROM mobile_app_auth_registry_migrations WHERE environment=$1",
      [environment],
    );
    if (
      prior.rows.length &&
      (prior.rows[0]?.source_digest !== digest ||
        prior.rows[0]?.client_count !== snapshot.length)
    )
      refuse("migration_source_conflict");
    await database.query(
      "INSERT INTO mobile_app_auth_registry_migrations(environment, source_digest, client_count, client_ids) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(environment) DO NOTHING",
      [
        environment,
        digest,
        snapshot.length,
        JSON.stringify(snapshot.map((record) => record.client_id)),
      ],
    );
    await database.query("COMMIT");
    return { clients: snapshot.length, digest };
  } catch (error) {
    await database.query("ROLLBACK");
    throw error;
  }
}

export async function verifyNativeRegistryMigration(
  database: MigrationDatabase,
  environment: "staging" | "production",
) {
  const result = await database.query(
    "SELECT source_digest, client_count, client_ids FROM mobile_app_auth_registry_migrations WHERE environment=$1",
    [environment],
  );
  const row = result.rows[0];
  if (
    result.rows.length !== 1 ||
    !row ||
    typeof row.source_digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(row.source_digest) ||
    typeof row.client_count !== "number" ||
    row.client_count < 1
  )
    refuse("complete_import_required");
  if (
    !Array.isArray(row.client_ids) ||
    row.client_ids.length !== row.client_count ||
    row.client_ids.some((id) => typeof id !== "string")
  )
    refuse("complete_import_required");
  const retained = await database.query(
    "SELECT count(*)::int AS count FROM mobile_app_auth_clients WHERE client_id = ANY($1::text[])",
    [row.client_ids],
  );
  if (retained.rows[0]?.count !== row.client_count)
    refuse("imported_registration_missing");
  return { clients: row.client_count, digest: row.source_digest };
}

if (import.meta.main) {
  let database: Client | undefined;
  try {
    const environment = process.env.ENVIRONMENT;
    if (
      !process.env.DATABASE_URL ||
      (environment !== "staging" && environment !== "production")
    )
      refuse("environment");
    const { url, ssl } = enforceTlsForRemote(process.env.DATABASE_URL);
    database = new Client({
      connectionString: url,
      ...(ssl ? { ssl } : {}),
      connectionTimeoutMillis: 10_000,
    });
    await database.connect();
    const identity = readDatabaseIdentityConfig({
      ...process.env,
      DATABASE_IDENTITY_GATE_MODE: "enforce",
      DATABASE_IDENTITY_ENVIRONMENT: environment,
    });
    await runDatabaseIdentityPreflight(identity, database);
    const result = process.argv.includes("--verify")
      ? await verifyNativeRegistryMigration(database, environment)
      : await migrateNativeRegistry(
          database,
          {
            primaryAppId: process.env.ELIZA_MOBILE_APP_AUTH_APP_ID,
            clients: process.env.ELIZA_MOBILE_APP_AUTH_CLIENTS_JSON,
            assetLinks: process.env.ELIZA_ANDROID_ASSET_LINKS_JSON,
            callbacks: process.env.ELIZA_NATIVE_AUTH_CALLBACKS_JSON,
          },
          environment,
        );
    console.log(JSON.stringify({ status: "verified", ...result }));
  } catch (error) {
    console.error(
      error instanceof Error &&
        error.message.startsWith("Native client migration refused:")
        ? error.message
        : "Native client migration failed; no credentials or registry data logged",
    );
    process.exitCode = 1;
  } finally {
    await database?.end();
  }
}
