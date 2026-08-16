----------------------------- MODULE AliasJournal -----------------------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Connections, ActiveConnection, AliasIds, Devices, MaxClock,
          ForeignConnection

EventIds == Devices \X (1..MaxClock)
Kinds == {"prepared", "dispatched", "outcomeUnknown", "failed",
          "observedEnabled", "observedDisabled", "deleted"}
LifecycleKinds == {"observedEnabled", "observedDisabled", "deleted"}
OutcomeKinds == LifecycleKinds \cup {"failed"}
TerminalKinds == OutcomeKinds \cup {"outcomeUnknown"}

EventType ==
    [eventId     : EventIds,
     connectionId : {ActiveConnection},
     aliasId     : AliasIds,
     kind        : Kinds,
     parents     : SUBSET EventIds]

EventResource(event) == <<event.connectionId, event.aliasId>>
EventIdsIn(journal) == {event.eventId : event \in journal}
OwnEvents(journal, device) ==
    {event \in journal : event.eventId[1] = device}

Merge(left, right) == left \cup right

Precedes(earlier, later) == earlier.eventId \in later.parents
Concurrent(left, right) == ~Precedes(left, right) /\ ~Precedes(right, left)

EventsFor(journal, resource) ==
    {event \in journal : EventResource(event) = resource}
EventsOfKind(journal, resource, kind) ==
    {event \in EventsFor(journal, resource) : event.kind = kind}
LatestLifecycleEvents(journal, resource) ==
    {event \in EventsFor(journal, resource) :
        /\ event.kind \in LifecycleKinds
        /\ ~\E later \in EventsFor(journal, resource) :
            /\ later.kind \in LifecycleKinds
            /\ Precedes(event, later)}

HasTombstone(journal, resource) ==
    EventsOfKind(journal, resource, "deleted") # {}

HasLifecycleConflict(journal, resource) ==
    \E enabled \in LatestLifecycleEvents(journal, resource),
       disabled \in LatestLifecycleEvents(journal, resource) :
        /\ enabled.kind = "observedEnabled"
        /\ disabled.kind = "observedDisabled"
        /\ Concurrent(enabled, disabled)

UnknownUnresolved(journal, resource) ==
    \E unknown \in EventsOfKind(journal, resource, "outcomeUnknown") :
        ~\E outcome \in EventsFor(journal, resource) :
            /\ outcome.kind \in OutcomeKinds
            /\ Precedes(unknown, outcome)

PhaseUnresolved(journal, resource, kind) ==
    \E phase \in EventsOfKind(journal, resource, kind) :
        ~\E later \in EventsFor(journal, resource) :
            /\ later.kind \in Kinds
            /\ Precedes(phase, later)

HasOperationConflict(journal, resource) ==
    \E left, right \in EventsFor(journal, resource) :
        /\ left.kind \in TerminalKinds
        /\ right.kind \in TerminalKinds
        /\ left.kind # right.kind
        /\ Concurrent(left, right)

Lifecycle(journal, resource) ==
    IF HasTombstone(journal, resource)
    THEN "deleted"
    ELSE IF \E event \in LatestLifecycleEvents(journal, resource) :
                event.kind = "observedDisabled"
         THEN "disabled"
         ELSE "enabled"

Operation(journal, resource) ==
    IF UnknownUnresolved(journal, resource)
    THEN "outcome-unknown"
    ELSE IF PhaseUnresolved(journal, resource, "failed")
         THEN "failed"
         ELSE IF PhaseUnresolved(journal, resource, "dispatched")
              THEN "dispatched"
              ELSE IF PhaseUnresolved(journal, resource, "prepared")
                   THEN "prepared"
                   ELSE "none"

Freshness(journal, resource) ==
    IF LatestLifecycleEvents(journal, resource) = {} THEN "stale" ELSE "current"

Consistency(journal, resource) ==
    IF HasLifecycleConflict(journal, resource) \/
       HasOperationConflict(journal, resource)
    THEN "conflicted"
    ELSE "clean"

Reduce(journal, resource) ==
    [lifecycle   |-> Lifecycle(journal, resource),
     operation   |-> Operation(journal, resource),
     freshness   |-> Freshness(journal, resource),
     consistency |-> Consistency(journal, resource)]

VARIABLES journals, beforeJournals, lastAction

variables == <<journals, beforeJournals, lastAction>>

Init ==
    /\ ActiveConnection \in Connections
    /\ ForeignConnection \in Connections \ {ActiveConnection}
    /\ journals = [device \in Devices |-> {}]
    /\ beforeJournals = journals
    /\ lastAction = "init"

NextClock(journal, device) == Cardinality(OwnEvents(journal, device)) + 1

Append(device, aliasId, kind) ==
    LET clock == NextClock(journals[device], device)
        event ==
            [eventId      |-> <<device, clock>>,
             connectionId |-> ActiveConnection,
             aliasId      |-> aliasId,
             kind         |-> kind,
             parents      |-> EventIdsIn(journals[device])]
    IN /\ clock \leq MaxClock
       /\ beforeJournals' = journals
       /\ journals' = [journals EXCEPT ![device] = @ \cup {event}]
       /\ lastAction' = "append"

Sync(target, source) ==
    /\ target # source
    /\ journals[target] # Merge(journals[target], journals[source])
    /\ beforeJournals' = journals
    /\ journals' =
        [journals EXCEPT ![target] = Merge(journals[target], journals[source])]
    /\ lastAction' = "sync"

RejectForeign ==
    /\ beforeJournals' = journals
    /\ journals' = journals
    /\ lastAction' = "rejectForeign"

Next ==
    \/ \E device \in Devices, aliasId \in AliasIds, kind \in Kinds :
           Append(device, aliasId, kind)
    \/ \E target, source \in Devices : Sync(target, source)
    \/ RejectForeign

Spec == Init /\ [][Next]_variables

TypeOK ==
    /\ journals \in [Devices -> SUBSET EventType]
    /\ beforeJournals \in [Devices -> SUBSET EventType]
    /\ lastAction \in {"init", "append", "sync", "rejectForeign"}

AppendOnly ==
    lastAction \in {"append", "sync", "rejectForeign"} =>
        \A device \in Devices : beforeJournals[device] \subseteq journals[device]

ConnectionScoped ==
    \A device \in Devices :
        \A event \in journals[device] : event.connectionId = ActiveConnection

CausalIdentifiersUnique ==
    \A device \in Devices :
        \A left, right \in journals[device] :
            left.eventId = right.eventId => left = right

CausalParentsExist ==
    \A device \in Devices :
        \A event \in journals[device] :
            event.parents \subseteq EventIdsIn(journals[device])

MergeCommutative ==
    \A left, right \in Devices :
        Merge(journals[left], journals[right]) =
            Merge(journals[right], journals[left])

MergeAssociative ==
    \A left, middle, right \in Devices :
        Merge(Merge(journals[left], journals[middle]), journals[right]) =
            Merge(journals[left], Merge(journals[middle], journals[right]))

MergeIdempotent ==
    \A device \in Devices : Merge(journals[device], journals[device]) = journals[device]

DeterministicReduction ==
    \A left, right \in Devices, aliasId \in AliasIds :
        journals[left] = journals[right] =>
            Reduce(journals[left], <<ActiveConnection, aliasId>>) =
                Reduce(journals[right], <<ActiveConnection, aliasId>>)

TombstonesPreventResurrection ==
    \A device \in Devices, aliasId \in AliasIds :
        HasTombstone(journals[device], <<ActiveConnection, aliasId>>) =>
            Lifecycle(journals[device], <<ActiveConnection, aliasId>>) = "deleted"

ConcurrentConflictsRemainExplicit ==
    \A device \in Devices, aliasId \in AliasIds :
        (HasLifecycleConflict(journals[device], <<ActiveConnection, aliasId>>) \/
         HasOperationConflict(journals[device], <<ActiveConnection, aliasId>>)) =>
            Consistency(journals[device], <<ActiveConnection, aliasId>>) = "conflicted"

UnknownOutcomesRemainExplicit ==
    \A device \in Devices, aliasId \in AliasIds :
        UnknownUnresolved(journals[device], <<ActiveConnection, aliasId>>) =>
            Operation(journals[device], <<ActiveConnection, aliasId>>) =
                "outcome-unknown"

=============================================================================
