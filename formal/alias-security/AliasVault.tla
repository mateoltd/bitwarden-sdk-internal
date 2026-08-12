------------------------------ MODULE AliasVault ------------------------------
EXTENDS FiniteSets, Naturals, TLC

CONSTANTS Connections, AliasIds, Ciphers, Payloads, NoRef, OtherAddress,
          CredentialSource

Resources == Connections \X AliasIds
Addresses == AliasIds \cup {OtherAddress}

AliasAddress(resource) == resource[2]

Reference(resource, address) ==
    [version          |-> 2,
     provider         |-> "simplelogin",
     providerInstance |-> "canonical-instance",
     connectionId     |-> resource[1],
     aliasId          |-> resource[2],
     address          |-> address]

CanonicalReference(resource) == Reference(resource, AliasAddress(resource))
StaleReference(resource) == Reference(resource, OtherAddress)

CurrentReferences ==
    {CanonicalReference(resource) : resource \in Resources} \cup
    {StaleReference(resource) : resource \in Resources}

ReferenceResource(reference) == <<reference.connectionId, reference.aliasId>>

ReferenceSources ==
    {"schema-version", "provider", "provider-instance", "connection-id",
     "alias-id", "address"}

SerializationEvent(reference) ==
    [reference |-> reference, sources |-> ReferenceSources]

ExpectedReferenceFields ==
    {"version", "provider", "providerInstance", "connectionId", "aliasId", "address"}

VARIABLES scope, references, usernames, unrelated, initialUnrelated,
          providerEnabled, deleted, writeCount, writtenResource, writtenScope,
          serializations, migrationVersion, migrationCandidates,
          migrationInputConnection, migrationStatus, migratedConnection,
          lastAction, lastResource, beforeVault, beforeDeleted

variables ==
    <<scope, references, usernames, unrelated, initialUnrelated,
      providerEnabled, deleted, writeCount, writtenResource, writtenScope,
      serializations, migrationVersion, migrationCandidates,
      migrationInputConnection, migrationStatus, migratedConnection,
      lastAction, lastResource, beforeVault, beforeDeleted>>

Vault ==
    [references |-> references, usernames |-> usernames, unrelated |-> unrelated]

InitialSerializations(refs) ==
    LET referenced == {cipher \in Ciphers : refs[cipher] # NoRef}
    IN {SerializationEvent(refs[cipher]) : cipher \in referenced}

Init ==
    /\ scope \in Connections
    /\ references \in [Ciphers -> CurrentReferences \cup {NoRef}]
    /\ usernames \in [Ciphers -> Addresses]
    /\ unrelated \in [Ciphers -> Payloads]
    /\ initialUnrelated = unrelated
    /\ providerEnabled \in [Resources -> BOOLEAN]
    /\ deleted = {}
    /\ writeCount = [cipher \in Ciphers |-> 0]
    /\ writtenResource = [cipher \in Ciphers |-> NoRef]
    /\ writtenScope = [cipher \in Ciphers |-> NoRef]
    /\ serializations = InitialSerializations(references)
    /\ migrationVersion \in {1, 2}
    /\ migrationCandidates \in SUBSET Connections
    /\ migrationInputConnection \in Connections
    /\ migrationStatus = "pending"
    /\ migratedConnection = NoRef
    /\ lastAction = "init"
    /\ lastResource = NoRef
    /\ beforeVault = Vault
    /\ beforeDeleted = deleted

Claims(cipher, resource) ==
    /\ resource[1] = scope
    /\ IF references[cipher] = NoRef
          THEN usernames[cipher] = AliasAddress(resource)
          ELSE ReferenceResource(references[cipher]) = resource

Claimers(resource) == {cipher \in Ciphers : Claims(cipher, resource)}

Desired(cipher, resource) ==
    /\ references[cipher] = CanonicalReference(resource)
    /\ usernames[cipher] = AliasAddress(resource)

Reconcile(cipher, resource) ==
    /\ resource \in Resources \ deleted
    /\ Claimers(resource) = {cipher}
    /\ ~Desired(cipher, resource)
    /\ references' = [references EXCEPT ![cipher] = CanonicalReference(resource)]
    /\ usernames' = [usernames EXCEPT ![cipher] = AliasAddress(resource)]
    /\ writeCount' = [writeCount EXCEPT ![cipher] = @ + 1]
    /\ writtenResource' = [writtenResource EXCEPT ![cipher] = resource]
    /\ writtenScope' = [writtenScope EXCEPT ![cipher] = scope]
    /\ serializations' = serializations \cup
            {SerializationEvent(CanonicalReference(resource))}
    /\ lastAction' = "reconcile"
    /\ UNCHANGED <<scope, unrelated, initialUnrelated, providerEnabled, deleted,
                    migrationVersion, migrationCandidates,
                    migrationInputConnection, migrationStatus,
                    migratedConnection, lastResource, beforeVault,
                    beforeDeleted>>

SwitchScope(connection) ==
    /\ connection # scope
    /\ scope' = connection
    /\ lastAction' = "scope"
    /\ UNCHANGED <<references, usernames, unrelated, initialUnrelated,
                    providerEnabled, deleted, writeCount, writtenResource,
                    writtenScope, serializations, migrationVersion,
                    migrationCandidates, migrationInputConnection,
                    migrationStatus, migratedConnection, lastResource,
                    beforeVault, beforeDeleted>>

SetProviderEnabled(resource, value) ==
    /\ resource \in Resources \ deleted
    /\ providerEnabled[resource] # value
    /\ beforeVault' = Vault
    /\ beforeDeleted' = deleted
    /\ providerEnabled' = [providerEnabled EXCEPT ![resource] = value]
    /\ lastAction' = "disable"
    /\ lastResource' = resource
    /\ UNCHANGED <<scope, references, usernames, unrelated, initialUnrelated,
                    deleted, writeCount, writtenResource, writtenScope,
                    serializations, migrationVersion, migrationCandidates,
                    migrationInputConnection, migrationStatus,
                    migratedConnection>>

DeleteProviderResource(resource) ==
    /\ resource \in Resources \ deleted
    /\ beforeVault' = Vault
    /\ beforeDeleted' = deleted
    /\ deleted' = deleted \cup {resource}
    /\ lastAction' = "delete"
    /\ lastResource' = resource
    /\ UNCHANGED <<scope, references, usernames, unrelated, initialUnrelated,
                    providerEnabled, writeCount, writtenResource, writtenScope,
                    serializations, migrationVersion, migrationCandidates,
                    migrationInputConnection, migrationStatus,
                    migratedConnection>>

MigrateLegacyUnique ==
    /\ migrationVersion = 1
    /\ migrationStatus = "pending"
    /\ Cardinality(migrationCandidates) = 1
    /\ migrationStatus' = "migrated"
    /\ migratedConnection' = CHOOSE connection \in migrationCandidates : TRUE
    /\ lastAction' = "migrateLegacy"
    /\ UNCHANGED <<scope, references, usernames, unrelated, initialUnrelated,
                    providerEnabled, deleted, writeCount, writtenResource,
                    writtenScope, serializations, migrationVersion,
                    migrationCandidates, migrationInputConnection,
                    lastResource, beforeVault, beforeDeleted>>

RejectLegacyMigration ==
    /\ migrationVersion = 1
    /\ migrationStatus = "pending"
    /\ Cardinality(migrationCandidates) # 1
    /\ migrationStatus' = "rejected"
    /\ migratedConnection' = NoRef
    /\ lastAction' = "rejectLegacy"
    /\ UNCHANGED <<scope, references, usernames, unrelated, initialUnrelated,
                    providerEnabled, deleted, writeCount, writtenResource,
                    writtenScope, serializations, migrationVersion,
                    migrationCandidates, migrationInputConnection,
                    lastResource, beforeVault, beforeDeleted>>

MigrateCurrentReference ==
    /\ migrationVersion = 2
    /\ migrationStatus = "pending"
    /\ migrationStatus' = "current"
    /\ migratedConnection' = migrationInputConnection
    /\ lastAction' = "migrateCurrent"
    /\ UNCHANGED <<scope, references, usernames, unrelated, initialUnrelated,
                    providerEnabled, deleted, writeCount, writtenResource,
                    writtenScope, serializations, migrationVersion,
                    migrationCandidates, migrationInputConnection,
                    lastResource, beforeVault, beforeDeleted>>

Next ==
    \/ \E cipher \in Ciphers, resource \in Resources : Reconcile(cipher, resource)
    \/ \E connection \in Connections : SwitchScope(connection)
    \/ \E resource \in Resources, value \in BOOLEAN :
           SetProviderEnabled(resource, value)
    \/ \E resource \in Resources : DeleteProviderResource(resource)
    \/ MigrateLegacyUnique
    \/ RejectLegacyMigration
    \/ MigrateCurrentReference

Spec == Init /\ [][Next]_variables

TypeOK ==
    /\ scope \in Connections
    /\ references \in [Ciphers -> CurrentReferences \cup {NoRef}]
    /\ usernames \in [Ciphers -> Addresses]
    /\ unrelated \in [Ciphers -> Payloads]
    /\ initialUnrelated \in [Ciphers -> Payloads]
    /\ providerEnabled \in [Resources -> BOOLEAN]
    /\ deleted \subseteq Resources
    /\ writeCount \in [Ciphers -> 0..1]
    /\ writtenResource \in [Ciphers -> Resources \cup {NoRef}]
    /\ writtenScope \in [Ciphers -> Connections \cup {NoRef}]
    /\ migrationVersion \in {1, 2}
    /\ migrationCandidates \in SUBSET Connections
    /\ migrationInputConnection \in Connections
    /\ migrationStatus \in {"pending", "migrated", "rejected", "current"}
    /\ migratedConnection \in Connections \cup {NoRef}

StableResourceNamespace ==
    /\ \A resource \in Resources :
           ReferenceResource(CanonicalReference(resource)) = resource
    /\ \A connectionA, connectionB \in Connections, aliasId \in AliasIds :
           connectionA # connectionB =>
             CanonicalReference(<<connectionA, aliasId>>) #
               CanonicalReference(<<connectionB, aliasId>>)

AuthorizedWrites ==
    \A cipher \in Ciphers :
        writeCount[cipher] > 0 =>
            /\ writtenResource[cipher][1] = writtenScope[cipher]
            /\ writtenResource[cipher] \in Resources

AmbiguousLegacyMigrationRejected ==
    migrationVersion = 1 /\ Cardinality(migrationCandidates) # 1 =>
        migrationStatus \in {"pending", "rejected"}

UniqueLegacyMigrationAuthorized ==
    migrationVersion = 1 /\ migrationStatus = "migrated" =>
        /\ Cardinality(migrationCandidates) = 1
        /\ migratedConnection \in migrationCandidates

CurrentMigrationIdempotent ==
    migrationVersion = 2 /\ migrationStatus = "current" =>
        migratedConnection = migrationInputConnection

ReconciliationIdempotent ==
    \A cipher \in Ciphers : writeCount[cipher] <= 1

UnrelatedVaultItemsPreserved == unrelated = initialUnrelated

ProviderDeletePreservesVault ==
    lastAction = "delete" =>
        /\ Vault = beforeVault
        /\ deleted = beforeDeleted \cup {lastResource}

ProviderDisablePreservesVault ==
    lastAction = "disable" =>
        /\ Vault = beforeVault
        /\ deleted = beforeDeleted

CanonicalReferenceSchema ==
    \A event \in serializations : DOMAIN event.reference = ExpectedReferenceFields

CredentialNonDisclosure ==
    \A event \in serializations : CredentialSource \notin event.sources

=============================================================================
