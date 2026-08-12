---------------------------- MODULE AliasLifecycle ----------------------------
EXTENDS Naturals, TLC

CONSTANTS Connections, AliasIds, Actors, MaxAttempts, NoValue

Resources == Connections \X AliasIds
Operations == {"setEnabled", "delete"}
ReadStates == {"read", "verify"}
TerminalStates == {"success", "denied", "notFound", "interference", "unknown"}
ProgramCounters == ReadStates \cup TerminalStates \cup {"toggle", "response", "delete"}

VARIABLES enabled, deleted, operation, target, connection, desired, pc,
          observed, response, attempts, mutationCount, deleteRequests,
          successFromRead, unknownAtCount, lastMutationTarget,
          lastMutationConnection, lastAction, beforeEnabled, beforeDeleted

variables ==
    <<enabled, deleted, operation, target, connection, desired, pc,
      observed, response, attempts, mutationCount, deleteRequests,
      successFromRead, unknownAtCount, lastMutationTarget,
      lastMutationConnection, lastAction, beforeEnabled, beforeDeleted>>

Init ==
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
    /\ lastAction = "init"
    /\ beforeEnabled = enabled
    /\ beforeDeleted = deleted

Authorized(actor) == connection[actor] = target[actor][1]

RememberNoProviderChange(action) ==
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ lastAction' = action

DenySet(actor) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] \in ReadStates
    /\ ~Authorized(actor)
    /\ pc' = [pc EXCEPT ![actor] = "denied"]
    /\ RememberNoProviderChange("deny")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection>>

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
                    lastMutationConnection>>

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
                    unknownAtCount, lastMutationTarget, lastMutationConnection>>

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
                    lastMutationConnection>>

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
                    lastMutationConnection>>

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
                    response, deleteRequests, successFromRead, unknownAtCount>>

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
                    lastMutationConnection>>

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
                    response, deleteRequests, successFromRead>>

ReceiveToggleResponse(actor, reported) ==
    /\ operation[actor] = "setEnabled"
    /\ pc[actor] = "response"
    /\ response' = [response EXCEPT ![actor] = reported]
    /\ pc' = [pc EXCEPT ![actor] = "verify"]
    /\ RememberNoProviderChange("response")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection>>

DenyDelete(actor) ==
    /\ operation[actor] = "delete"
    /\ pc[actor] = "delete"
    /\ ~Authorized(actor)
    /\ pc' = [pc EXCEPT ![actor] = "denied"]
    /\ RememberNoProviderChange("deny")
    /\ UNCHANGED <<enabled, deleted, operation, target, connection, desired,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection>>

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
                    response, attempts, successFromRead, unknownAtCount>>

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
                    response, attempts, successFromRead>>

ExternalToggle(resource) ==
    /\ resource \in Resources \ deleted
    /\ enabled' = [enabled EXCEPT ![resource] = ~@]
    /\ lastAction' = "external"
    /\ beforeEnabled' = enabled
    /\ beforeDeleted' = deleted
    /\ UNCHANGED <<deleted, operation, target, connection, desired, pc,
                    observed, response, attempts, mutationCount, deleteRequests,
                    successFromRead, unknownAtCount, lastMutationTarget,
                    lastMutationConnection>>

ClientStep(actor) ==
    \/ DenySet(actor)
    \/ ReadDeleted(actor)
    \/ ReadDesired(actor)
    \/ ReadNeedsToggle(actor)
    \/ ReadExhausted(actor)
    \/ Toggle(actor)
    \/ ToggleTargetDeleted(actor)
    \/ \E applied \in BOOLEAN : ToggleOutcomeLost(actor, applied)
    \/ \E reported \in BOOLEAN : ReceiveToggleResponse(actor, reported)
    \/ DenyDelete(actor)
    \/ \E applied \in BOOLEAN : DeleteResponse(actor, applied)
    \/ \E applied \in BOOLEAN : DeleteOutcomeLost(actor, applied)

ReliableClientStep(actor) ==
    \/ DenySet(actor)
    \/ ReadDeleted(actor)
    \/ ReadDesired(actor)
    \/ ReadNeedsToggle(actor)
    \/ ReadExhausted(actor)
    \/ Toggle(actor)
    \/ ToggleTargetDeleted(actor)
    \/ \E reported \in BOOLEAN : ReceiveToggleResponse(actor, reported)
    \/ DenyDelete(actor)
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

StableMutationTarget ==
    \A actor \in Actors :
        mutationCount[actor] > 0 =>
            /\ lastMutationTarget[actor] = target[actor]
            /\ lastMutationConnection[actor] = connection[actor]

AuthorizedMutations ==
    \A actor \in Actors :
        mutationCount[actor] > 0 => connection[actor] = target[actor][1]

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

DeleteDoesNotDisable == lastAction = "delete" => enabled = beforeEnabled

DisableDoesNotDelete == lastAction = "toggle" => deleted = beforeDeleted

BoundedInterference ==
    \A actor \in Actors : attempts[actor] <= MaxAttempts

Terminates ==
    \A actor \in Actors : <>(pc[actor] \in TerminalStates)

AuthorizedSetConverges ==
    \A actor \in Actors :
        (operation[actor] = "setEnabled" /\ Authorized(actor))
            ~> (pc[actor] = "success")

=============================================================================
