// Required by frozen clients 018085075bfb18421bb22e7793360a6fd762da1d (.1051 API).
import {
  Fido2CredentialFullView,
  ManagedSettingsClient,
  ManagementProfile,
  PasswordManagerClient,
  PolicyClient,
  SendEncryptionType,
  SharedUnlockDriver,
  SharedUnlockPeer,
  SymmetricKey,
  UserId,
} from "@bitwarden/sdk-internal";

export function plaintextFidoKey(value: string): Fido2CredentialFullView["keyValue"] {
  return value;
}
export function brandedKey(value: SymmetricKey): string {
  return value;
}
// The SDK must retain the upstream nominal key boundary.
// @ts-expect-error Raw strings are not validated SDK symmetric keys.
const invalidKey: SymmetricKey = "unvalidated";
void invalidKey;

export function currentClients(
  client: PasswordManagerClient,
  profile: ManagementProfile,
  driver: SharedUnlockDriver,
  userId: UserId,
  key: SymmetricKey,
) {
  const managed = new ManagedSettingsClient();
  managed.update_profile(profile);
  const policies: PolicyClient = client.policies();
  const peer = new SharedUnlockPeer("Browser", driver);
  const unlock: Promise<void> = driver.unlock_user(userId, key);
  return { managed, policies, peer, unlock, sends: client.sends(), version: SendEncryptionType.V1 };
}
