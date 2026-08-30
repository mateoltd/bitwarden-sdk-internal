---------------------------- MODULE AliasLifecycle ----------------------------
EXTENDS Naturals, TLC

CONSTANTS Connections, AliasIds, Actors, MaxAttempts, NoValue, CapabilityConnection

Resources == Connections \X AliasIds
Operations == {"setEnabled", "delete"}
ReadStates == {"read", "verify"}
TerminalStates ==
    {"success", "denied", "unsupported", "notFound", "interference", "unknown"}
ProgramCounters == ReadStates \cup TerminalStates \cup {"toggle", "response", "delete"}

VARIABLES enabled, deleted, operation, target, connection, desired, pc,
          observed, response, attempts, mutationCount, deleteRequests,
          successFromRead, unknownAtCount, lastMutationTarget,
          lastMutationConnection, connectionCapabilities, lastAction,
          beforeEnabled, beforeDeleted

variables ==
    <<enabled, deleted, operation, target, connection, desired, pc,
      observed, response, attempts, mutationCount, deleteRequests,
      successFromRead, unknownAtCount, lastMutationTarget,
      lastMutationConnection, connectionCapabilities, lastAction,
      beforeEnabled, beforeDeleted>>

Init ==
    /\ CapabilityConnection \in Connections
    /\ enabled \in [Resources -> BOOLEAN]
    /\ deleted = {}
    /\ operation \in [Actors -> Operations]
    /\ target \in [Actors -> Resources]
    /\ connection \in [Actors -> Connections]
    /\ desired \in [Actors -> BOOLEAN]
    /\ pc = [actor \in Actors |->
            IF operation[actor] = "setEnabled" THEN "read" ELSE "delete"]
    /\ observed = [actor \in Actors |-> NoValue]
    /\ response = [actor \in Actors |-> NoValue]
    /\ attempts = [actor \in Actors |-> 0]
    /\ mutationCount = [actor \in Actors |-> 0]
    /\ deleteRequests = [actor \in Actors |-> 0]
    /\ successFromRead = [actor \in Actors |-> FALSE]
    /\ unknownAtCount = [actor \in Actors |-> 0]
    /\ lastMutationTarget = [actor \in Actors |-> NoValue]
    /\ lastMutationConnection = [actor \in Actors |-> NoValue]
    /\ connectionCapabilities =
        [candidate \in Connections |->
            IF candidate = CapabilityConnection THEN Operations ELSE {}]
    /\ lastAction = "init"
    /\ beforeEnabled = enabled
    /\ beforeDeleted = deleted

ConnectionScoped(actor) == connection[actor] = target[actor][1]
CapabilitySupported(actor) == operation[actor] \in connectionCapabilities[connection[actor]]
Authorized(actor) == ConnectionScoped(actor) /\ CapabilitySupported(actor)

RememberNoProviderChange(action) ==
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ lastAction' = action

DenySetScope(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ ~ConnectionScoped(actor)
    /\ pc' = [pc EXCEPT ![actor] = "denied"]
    /\ RememberNoProviderChange("deny")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

DenySetCapability(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ ConnectionScoped(actor)
    /\ ~CapabilitySupported(actor)
    /\ pc' = [pc EXCEPT ![actor] = "unsupported"]
    /\ RememberNoProviderChange("unsupported")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

ReadDeleted(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ Authorized(actor)
    /\ target[actor] \in deleted
    /\ pc' = [pc EXCEPT ![actor] = "notFound"]
    /\ RememberNoProviderChange("read")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

ReadDesired(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ Authorized(actor)
    /\ target[actor] \notin deleted
    /\ enabled[target[actor]] = desired[actor]
    /\ observed' = [observed EXCEPT ![actor] = enabled[target[actor]]]
    /\ successFromRead' = [successFromRead EXCEPT ![actor] = TRUE]
    /\ pc' = [pc EXCEPT ![actor] = "success"]
    /\ RememberNoProviderChange("read")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    response, attempts, mutationCount, deleteRequests,
                    unknownAtCount, lastMutationTarget, lastMutationConnection,
                    connectionCapabilities>>

ReadNeedsToggle(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ Authorized(actor)
    /\ target[actor] \notin deleted
    /\ enabled[target[actor]] # desired[actor]
    /\ attempts[actor] < MaxAttempts
    /\ observed' = [observed EXCEPT ![actor] = enabled[target[actor]]]
    /\ pc' = [pc EXCEPT ![actor] = "toggle"]
    /\ RememberNoProviderChange("read")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

ReadExhausted(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ Authorized(actor)
    /\ target[actor] \notin deleted
    /\ enabled[target[actor]] # desired[actor]
    /\ attempts[actor] = MaxAttempts
    /\ observed' = [observed EXCEPT ![actor] = enabled[target[actor]]]
    /\ pc' = [pc EXCEPT ![actor] = "interference"]
    /\ RememberNoProviderChange("read")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

Toggle(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] = "toggle"
    /\ Authorized(actor)
    /\ target[actor] \notin deleted
    /\ enabled' = [enabled EXCEPT ![target[actor]] = ~@]
    /\ attempts' = [attempts EXCEPT ![actor] = @ + 1]
    /\ mutationCount' = [mutationCount EXCEPT ![actor] = @ + 1]
    /\ lastMutationTarget' = [lastMutationTarget EXCEPT ![actor] = target[actor]]
    /\ lastMutationConnection' =
            [lastMutationConnection EXCEPT ![actor] = connection[actor]]
    /\ pc' = [pc EXCEPT ![actor] = "response"]
    /\ lastAction' = "toggle"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<deleted, operation, target, connection, desired, observed,
                    response, deleteRequests, successFromRead, unknownAtCount,
                    connectionCapabilities>>

ToggleTargetDeleted(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] = "toggle"
    /\ Authorized(actor)
    /\ target[actor] \in deleted
    /\ pc' = [pc EXCEPT ![actor] = "notFound"]
    /\ RememberNoProviderChange("toggleNotFound")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

ToggleOutcomeLost(actor, applied) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] = "toggle"
    /\ Authorized(actor)
    /\ target[actor] \notin deleted
    /\ enabled' = IF applied
            THEN [enabled EXCEPT ![target[actor]] = ~@]
            ELSE enabled
    /\ attempts' = [attempts EXCEPT ![actor] = @ + 1]
    /\ mutationCount' = [mutationCount EXCEPT ![actor] = @ + 1]
    /\ unknownAtCount' = [unknownAtCount EXCEPT ![actor] = mutationCount[actor] + 1]
    /\ lastMutationTarget' = [lastMutationTarget EXCEPT ![actor] = target[actor]]
    /\ lastMutationConnection' =
            [lastMutationConnection EXCEPT ![actor] = connection[actor]]
    /\ pc' = [pc EXCEPT ![actor] = "unknown"]
    /\ lastAction' = "toggleLost"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<deleted, operation, target, connection, desired, observed,
                    response, deleteRequests, successFromRead,
                    connectionCapabilities>>

ReceiveToggleResponse(actor, reported) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] = "response"
    /\ response' = [response EXCEPT ![actor] = reported]
    /\ pc' = [pc EXCEPT ![actor] = "verify"]
    /\ RememberNoProviderChange("response")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

DenyDeleteScope(actor) ==
    /\ operation[actor] = "delete"
    /\ pc[actor] = "delete"
    /\ ~ConnectionScoped(actor)
    /\ pc' = [pc EXCEPT ![actor] = "denied"]
    /\ RememberNoProviderChange("deny")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

DenyDeleteCapability(actor) ==
    /\ operation[actor] = "delete"
    /\ pc[actor] = "delete"
    /\ ConnectionScoped(actor)
    /\ ~CapabilitySupported(actor)
    /\ pc' = [pc EXCEPT ![actor] = "unsupported"]
    /\ RememberNoProviderChange("unsupported")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

DeleteResponse(actor, applied) ==
    /\ operation[actor] = "delete"
    /\ pc[actor] = "delete"
    /\ Authorized(actor)
    /\ deleted' = IF applied THEN deleted \cup {target[actor]} ELSE deleted
    /\ mutationCount' = [mutationCount EXCEPT ![actor] = @ + 1]
    /\ deleteRequests' = [deleteRequests EXCEPT ![actor] = @ + 1]
    /\ lastMutationTarget' = [lastMutationTarget EXCEPT ![actor] = target[actor]]
    /\ lastMutationConnection' =
            [lastMutationConnection EXCEPT ![actor] = connection[actor]]
    /\ pc' = [pc EXCEPT ![actor] = "success"]
    /\ lastAction' = "delete"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<enabled, operation, target, connection, desired, observed,
                    response, attempts, successFromRead, unknownAtCount,
                    connectionCapabilities>>

DeleteOutcomeLost(actor, applied) ==
    /\ operation[actor] = "delete"
    /\ pc[actor] = "delete"
    /\ Authorized(actor)
    /\ deleted' = IF applied THEN deleted \cup {target[actor]} ELSE deleted
    /\ mutationCount' = [mutationCount EXCEPT ![actor] = @ + 1]
    /\ deleteRequests' = [deleteRequests EXCEPT ![actor] = @ + 1]
    /\ unknownAtCount' = [unknownAtCount EXCEPT ![actor] = mutationCount[actor] + 1]
    /\ lastMutationTarget' = [lastMutationTarget EXCEPT ![actor] = target[actor]]
    /\ lastMutationConnection' =
            [lastMutationConnection EXCEPT ![actor] = connection[actor]]
    /\ pc' = [pc EXCEPT ![actor] = "unknown"]
    /\ lastAction' = "deleteLost"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<enabled, operation, target, connection, desired, observed,
                    response, attempts, successFromRead,
                    connectionCapabilities>>

ExternalToggle(resource) ==
    /\ resource \in Resources \ deleted
    /\ enabled' = [enabled EXCEPT ![resource] = ~@]
    /\ lastAction' = "external"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<deleted, operation, target, connection, desired, pc,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection, connectionCapabilities>>

ClientStep(actor) ==
    \/ DenySetScope(actor)
    \/ DenySetCapability(actor)
    \/ ReadDeleted(actor)
    \/ ReadDesired(actor)
    \/ ReadNeedsToggle(actor)
    \/ ReadExhausted(actor)
    \/ Toggle(actor)
    \/ ToggleTargetDeleted(actor)
    \/ \E applied \in BOOLEAN : ToggleOutcomeLost(actor, applied)
    \/ \E reported \in BOOLEAN : ReceiveToggleResponse(actor, reported)
    \/ DenyDeleteScope(actor)
    \/ DenyDeleteCapability(actor)
    \/ \E applied \in BOOLEAN : DeleteResponse(actor, applied)
    \/ \E applied \in BOOLEAN : DeleteOutcomeLost(actor, applied)

ReliableClientStep(actor) ==
    \/ DenySetScope(actor)
    \/ DenySetCapability(actor)
    \/ ReadDeleted(actor)
    \/ ReadDesired(actor)
    \/ ReadNeedsToggle(actor)
    \/ ReadExhausted(actor)
    \/ Toggle(actor)
    \/ ToggleTargetDeleted(actor)
    \/ \E reported \in BOOLEAN : ReceiveToggleResponse(actor, reported)
    \/ DenyDeleteScope(actor)
    \/ DenyDeleteCapability(actor)
    \/ \E applied \in BOOLEAN : DeleteResponse(actor, applied)

ClientNext == \E actor \in Actors : ClientStep(actor)
ReliableClientNext == \E actor \in Actors : ReliableClientStep(actor)

Next == ClientNext \/ \E resource \in Resources : ExternalToggle(resource)

Spec ==
    /\ Init
    /\ [][Next]_variables
    /\ \A actor \in Actors : WF_variables(ClientStep(actor))

ReliableQuiescentSpec ==
    /\ Init
    /\ [][ReliableClientNext]_variables
    /\ \A actor \in Actors : WF_variables(ReliableClientStep(actor))

TypeOK ==
    /\ enabled \in [Resources -> BOOLEAN]
    /\ deleted \subseteq Resources
    /\ operation \in [Actors -> Operations]
    /\ target \in [Actors -> Resources]
    /\ connection \in [Actors -> Connections]
    /\ desired \in [Actors -> BOOLEAN]
    /\ pc \in [Actors -> ProgramCounters]
    /\ observed \in [Actors -> BOOLEAN \cup {NoValue}]
    /\ response \in [Actors -> BOOLEAN \cup {NoValue}]
    /\ attempts \in [Actors -> 0..MaxAttempts]
    /\ deleteRequests \in [Actors -> 0..1]
    /\ connectionCapabilities \in [Connections -> SUBSET Operations]

StableMutationTarget ==
    \A actor \in Actors :
        mutationCount[actor] > 0 =>
            /\ lastMutationTarget[actor] = target[actor]
            /\ lastMutationConnection[actor] = connection[actor]

AuthorizedMutations ==
    \A actor \in Actors :
        mutationCount[actor] > 0 => Authorized(actor)

UnsupportedNeverMutates ==
    \A actor \in Actors :
        ~CapabilitySupported(actor) => mutationCount[actor] = 0

ExplicitCapabilityFailure ==
    \A actor \in Actors :
        /\ (pc[actor] = "unsupported" =>
                ConnectionScoped(actor) /\ ~CapabilitySupported(actor))
        /\ (pc[actor] = "denied" => ~ConnectionScoped(actor))

SuccessRequiresVerifiedRead ==
    \A actor \in Actors :
        operation[actor] = "setEnabled" /\ pc[actor] = "success" =>
            /\ successFromRead[actor]
            /\ observed[actor] = desired[actor]

ReplayedResponseIgnored ==
    lastAction = "response" =>
        /\ enabled = beforeEnabled
        /\ deleted = beforeDeleted

UnknownOutcomeNotReplayed ==
    \A actor \in Actors :
        pc[actor] = "unknown" => mutationCount[actor] = unknownAtCount[actor]

DeleteDispatchedAtMostOnce ==
    \A actor \in Actors : deleteRequests[actor] <= 1

DeleteDoesNotDisable ==
    lastAction \in {"delete", "deleteLost"} => enabled = beforeEnabled

DisableDoesNotDelete ==
    lastAction \in {"toggle", "toggleLost"} => deleted = beforeDeleted

BoundedInterference ==
    \A actor \in Actors : attempts[actor] <= MaxAttempts

Terminates ==
    \A actor \in Actors : <>(pc[actor] \in TerminalStates)

AuthorizedSetConverges ==
    \A actor \in Actors :
        (operation[actor] = "setEnabled" /\ Authorized(actor))
            ~> (pc[actor] = "success")

=============================================================================
