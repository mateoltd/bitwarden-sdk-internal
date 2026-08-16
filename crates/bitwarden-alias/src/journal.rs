use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    ALIAS_CONTRACT_VERSION, AliasError, AliasErrorCode, AliasIdentity, AliasLifecycleState,
    AliasOperationKind, models::validate_random_id,
};

/// Current encrypted journal schema version.
pub const ALIAS_JOURNAL_VERSION: u32 = ALIAS_CONTRACT_VERSION;
/// Maximum number of events accepted in one journal.
pub const MAX_JOURNAL_EVENTS: usize = 10_000;
/// Maximum number of vector-clock entries accepted on one event.
pub const MAX_CAUSAL_ENTRIES: usize = 128;

/// One entry in an event's vector clock. Entries must be sorted by replica ID and unique.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasCausalEntry {
    /// UUID v4 of the observed replica.
    pub replica_id: String,
    /// Greatest observed sequence for that replica.
    pub sequence: u64,
}

impl core::fmt::Debug for AliasCausalEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasCausalEntry([REDACTED])")
    }
}

/// Durable operation phase. A dispatched operation is never reduced to ordinary failure merely
/// because its response was lost.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliasOperationPhase {
    /// The operation is durable but has not been dispatched.
    Prepared,
    /// The mutation was dispatched and has no confirmed outcome yet.
    Dispatched,
    /// The adapter confirmed the operation and any resulting state.
    Acknowledged,
    /// A mutation may have committed and must be reconciled.
    OutcomeUnknown,
    /// The operation failed before an ambiguous mutation outcome.
    Failed,
}

/// Secret-free encrypted journal event. Its closed schema deliberately has nowhere to place an
/// endpoint, credential, request/response body, header, URL query, or provider-native payload.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasJournalEvent {
    /// Journal schema version.
    pub version: u32,
    /// Globally unique UUID v4 for this immutable event.
    pub event_id: String,
    /// UUID v4 grouping all phases of one logical operation.
    pub operation_id: String,
    /// UUID v4 of the replica that appended this event.
    pub replica_id: String,
    /// Strictly increasing sequence within the replica.
    pub sequence: u64,
    /// Canonically sorted vector clock of observed predecessor events.
    pub causal: Vec<AliasCausalEntry>,
    /// Provider-neutral operation category.
    pub operation: AliasOperationKind,
    /// Durable phase of the operation.
    pub phase: AliasOperationPhase,
    /// Absent for create until an adapter acknowledges a stable remote identity.
    pub target: Option<AliasIdentity>,
    /// Desired or acknowledged lifecycle, kept separate from operation phase.
    pub lifecycle: Option<AliasLifecycleState>,
    /// Only a stable provider-neutral category is retained.
    pub error: Option<AliasErrorCode>,
}

impl core::fmt::Debug for AliasJournalEvent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasJournalEvent([REDACTED])")
    }
}

impl AliasJournalEvent {
    /// Validates this event's schema, causal clock, and operation semantics.
    pub fn validate(&self) -> Result<(), AliasError> {
        if self.version != ALIAS_JOURNAL_VERSION || self.sequence == 0 {
            return Err(AliasError::InvalidInput);
        }
        validate_random_id(&self.event_id)?;
        validate_random_id(&self.operation_id)?;
        validate_random_id(&self.replica_id)?;
        if self.causal.len() > MAX_CAUSAL_ENTRIES {
            return Err(AliasError::InvalidInput);
        }
        let mut previous: Option<&str> = None;
        let mut own_causal_sequence = None;
        for entry in &self.causal {
            validate_random_id(&entry.replica_id)?;
            if entry.sequence == 0
                || previous.is_some_and(|value| value >= entry.replica_id.as_str())
            {
                return Err(AliasError::InvalidInput);
            }
            if entry.replica_id == self.replica_id {
                if entry.sequence >= self.sequence {
                    return Err(AliasError::InvalidInput);
                }
                own_causal_sequence = Some(entry.sequence);
            }
            previous = Some(&entry.replica_id);
        }
        if (self.sequence == 1 && own_causal_sequence.is_some())
            || (self.sequence > 1 && own_causal_sequence != Some(self.sequence - 1))
        {
            return Err(AliasError::InvalidInput);
        }
        if let Some(target) = &self.target {
            target.validate()?;
        }
        let target_required = matches!(
            self.operation,
            AliasOperationKind::Get
                | AliasOperationKind::Enable
                | AliasOperationKind::Disable
                | AliasOperationKind::Delete
                | AliasOperationKind::CreateSendReplyIdentity
                | AliasOperationKind::ListSendReplyIdentities
                | AliasOperationKind::RemoveSendReplyIdentity
                | AliasOperationKind::SetSendReplyBlocked
        );
        if target_required && self.target.is_none() {
            return Err(AliasError::InvalidInput);
        }
        if matches!(
            self.operation,
            AliasOperationKind::List | AliasOperationKind::Reconcile
        ) && self.target.is_some()
        {
            return Err(AliasError::InvalidInput);
        }
        match self.operation {
            AliasOperationKind::Enable
                if self.lifecycle.is_some()
                    && self.lifecycle != Some(AliasLifecycleState::Enabled) =>
            {
                return Err(AliasError::InvalidInput);
            }
            AliasOperationKind::Disable
                if self.lifecycle.is_some()
                    && self.lifecycle != Some(AliasLifecycleState::Disabled) =>
            {
                return Err(AliasError::InvalidInput);
            }
            AliasOperationKind::Delete
                if self.lifecycle.is_some()
                    && self.lifecycle != Some(AliasLifecycleState::Deleted) =>
            {
                return Err(AliasError::InvalidInput);
            }
            AliasOperationKind::Create if self.lifecycle == Some(AliasLifecycleState::Deleted) => {
                return Err(AliasError::InvalidInput);
            }
            AliasOperationKind::List
            | AliasOperationKind::CreateSendReplyIdentity
            | AliasOperationKind::ListSendReplyIdentities
            | AliasOperationKind::RemoveSendReplyIdentity
            | AliasOperationKind::SetSendReplyBlocked
            | AliasOperationKind::Reconcile
                if self.lifecycle.is_some() =>
            {
                return Err(AliasError::InvalidInput);
            }
            _ => {}
        }
        match self.phase {
            AliasOperationPhase::Prepared | AliasOperationPhase::Dispatched => {
                if self.error.is_some() {
                    return Err(AliasError::InvalidInput);
                }
            }
            AliasOperationPhase::Acknowledged => {
                let alias_state_observation = matches!(
                    self.operation,
                    AliasOperationKind::Create
                        | AliasOperationKind::Get
                        | AliasOperationKind::Enable
                        | AliasOperationKind::Disable
                        | AliasOperationKind::Delete
                );
                if self.error.is_some()
                    || (alias_state_observation
                        && (self.target.is_none() || self.lifecycle.is_none()))
                {
                    return Err(AliasError::InvalidInput);
                }
            }
            AliasOperationPhase::OutcomeUnknown => {
                if self.error != Some(AliasErrorCode::OutcomeUnknown) {
                    return Err(AliasError::InvalidInput);
                }
            }
            AliasOperationPhase::Failed => {
                if self.error.is_none() || self.error == Some(AliasErrorCode::OutcomeUnknown) {
                    return Err(AliasError::InvalidInput);
                }
            }
        }
        Ok(())
    }
}

/// Canonically ordered append-only event set.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasJournal {
    /// Journal schema version.
    pub version: u32,
    /// Stable authorization scope for every event, including create events without a remote ID.
    pub connection_id: String,
    /// Canonically ordered immutable event set.
    pub events: Vec<AliasJournalEvent>,
}

impl core::fmt::Debug for AliasJournal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasJournal([REDACTED])")
    }
}

impl AliasJournal {
    /// Creates an empty canonical journal for one stable connection.
    pub fn empty(connection_id: String) -> Result<Self, AliasError> {
        validate_random_id(&connection_id)?;
        Self {
            version: ALIAS_JOURNAL_VERSION,
            connection_id,
            events: Vec::new(),
        }
        .canonicalize()
    }

    /// Validates, deduplicates, and deterministically orders journal events.
    pub fn canonicalize(mut self) -> Result<Self, AliasError> {
        if self.version != ALIAS_JOURNAL_VERSION || self.events.len() > MAX_JOURNAL_EVENTS {
            return Err(AliasError::InvalidInput);
        }
        validate_random_id(&self.connection_id)?;
        for event in &self.events {
            event.validate()?;
            if event
                .target
                .as_ref()
                .is_some_and(|target| target.connection_id != self.connection_id)
            {
                return Err(AliasError::SyncConflict);
            }
        }
        self.events
            .sort_by(|left, right| left.event_id.cmp(&right.event_id));

        let mut canonical_events: Vec<AliasJournalEvent> = Vec::with_capacity(self.events.len());
        for event in self.events {
            if let Some(existing) = canonical_events.last()
                && existing.event_id == event.event_id
            {
                if serde_json::to_vec(existing).map_err(|_| AliasError::LocalSecurityFailure)?
                    != serde_json::to_vec(&event).map_err(|_| AliasError::LocalSecurityFailure)?
                {
                    return Err(AliasError::SyncConflict);
                }
                continue;
            }
            canonical_events.push(event);
        }
        self.events = canonical_events;

        let mut coordinates = BTreeSet::new();
        let mut operation_facts =
            BTreeMap::<&str, (AliasOperationKind, Option<&AliasIdentity>)>::new();
        for event in &self.events {
            if !coordinates.insert((event.replica_id.as_str(), event.sequence)) {
                return Err(AliasError::SyncConflict);
            }
            match operation_facts.get_mut(event.operation_id.as_str()) {
                Some((operation, target)) => {
                    let target_changed = match (target.as_ref(), event.target.as_ref()) {
                        (Some(left), Some(right)) => {
                            !same_identity_snapshot(Some(*left), Some(right))
                        }
                        _ => false,
                    };
                    if *operation != event.operation || target_changed {
                        return Err(AliasError::SyncConflict);
                    }
                    if target.is_none() && event.target.is_some() {
                        *target = event.target.as_ref();
                    }
                }
                None => {
                    operation_facts.insert(
                        event.operation_id.as_str(),
                        (event.operation, event.target.as_ref()),
                    );
                }
            }
        }
        for event in &self.events {
            if event
                .causal
                .iter()
                .any(|entry| !coordinates.contains(&(entry.replica_id.as_str(), entry.sequence)))
            {
                return Err(AliasError::InvalidInput);
            }
        }

        let mut operation_history = BTreeMap::<(&str, &str), Vec<&AliasJournalEvent>>::new();
        for event in &self.events {
            operation_history
                .entry((event.operation_id.as_str(), event.replica_id.as_str()))
                .or_default()
                .push(event);
        }
        for history in operation_history.values_mut() {
            history.sort_by_key(|event| event.sequence);
        }
        for event in &self.events {
            for causal in &event.causal {
                let Some(history) = operation_history
                    .get(&(event.operation_id.as_str(), causal.replica_id.as_str()))
                else {
                    continue;
                };
                let boundary = history.partition_point(|prior| prior.sequence <= causal.sequence);
                if let Some(prior) = history[..boundary].last() {
                    validate_phase_progression(prior, event)?;
                }
            }
        }
        Ok(self)
    }

    /// Pure set-union merge. Canonical ordering makes it commutative, associative, and
    /// idempotent; a reused event ID with different content fails closed as a conflict.
    pub fn merge(&self, other: &Self) -> Result<Self, AliasError> {
        let left = self.clone().canonicalize()?;
        let right = other.clone().canonicalize()?;
        if left.connection_id != right.connection_id {
            return Err(AliasError::SyncConflict);
        }
        let connection_id = left.connection_id.clone();
        let mut events = BTreeMap::<String, AliasJournalEvent>::new();
        for event in left.events.into_iter().chain(right.events) {
            if let Some(existing) = events.get(&event.event_id) {
                if serde_json::to_vec(existing).map_err(|_| AliasError::LocalSecurityFailure)?
                    != serde_json::to_vec(&event).map_err(|_| AliasError::LocalSecurityFailure)?
                {
                    return Err(AliasError::SyncConflict);
                }
            } else {
                events.insert(event.event_id.clone(), event);
            }
        }
        if events.len() > MAX_JOURNAL_EVENTS {
            return Err(AliasError::InvalidInput);
        }
        Ok(Self {
            version: ALIAS_JOURNAL_VERSION,
            connection_id,
            events: events.into_values().collect(),
        })
    }

    /// Reduces canonical facts into deterministic operation, resource, and conflict state.
    pub fn reduce(&self) -> Result<AliasJournalState, AliasError> {
        let journal = self.clone().canonicalize()?;
        let mut operations = BTreeMap::<String, AliasReducedOperation>::new();
        let mut resources = BTreeMap::<String, AliasReducedResource>::new();
        let mut conflicts = BTreeSet::<String>::new();

        for event in journal.events {
            let operation = operations
                .entry(event.operation_id.clone())
                .or_insert_with(|| AliasReducedOperation::from_event(&event));
            if operation.operation != event.operation {
                conflicts.insert(event.operation_id.clone());
                continue;
            }
            let event_after_operation = observes(
                &event.replica_id,
                event.sequence,
                &event.causal,
                &operation.replica_id,
                operation.sequence,
            );
            let operation_after_event = observes(
                &operation.replica_id,
                operation.sequence,
                &operation.causal,
                &event.replica_id,
                event.sequence,
            );
            if is_terminal(operation.phase)
                && is_terminal(event.phase)
                && (operation.phase != event.phase
                    || operation.lifecycle != event.lifecycle
                    || !same_identity_snapshot(operation.target.as_ref(), event.target.as_ref()))
                && !event_after_operation
                && !operation_after_event
            {
                conflicts.insert(event.operation_id.clone());
            }
            if event_after_operation
                || (!operation_after_event
                    && (
                        event.sequence,
                        event.replica_id.as_str(),
                        event.event_id.as_str(),
                    ) > (
                        operation.sequence,
                        operation.replica_id.as_str(),
                        operation.event_id.as_str(),
                    ))
            {
                *operation = AliasReducedOperation::from_event(&event);
            }

            if event.phase == AliasOperationPhase::Acknowledged
                && let (Some(target), Some(lifecycle)) = (event.target, event.lifecycle)
            {
                let key = resource_key(&target);
                let candidate = AliasReducedResource {
                    identity: target,
                    lifecycle,
                    tombstoned: lifecycle == AliasLifecycleState::Deleted,
                    sequence: event.sequence,
                    replica_id: event.replica_id,
                    event_id: event.event_id,
                    causal: event.causal,
                };
                match resources.get(&key) {
                    Some(current) if current.tombstoned && !candidate.tombstoned => {
                        conflicts.insert(key);
                    }
                    Some(current) if candidate.tombstoned && !current.tombstoned => {
                        if !observes(
                            &candidate.replica_id,
                            candidate.sequence,
                            &candidate.causal,
                            &current.replica_id,
                            current.sequence,
                        ) {
                            conflicts.insert(key.clone());
                        }
                        resources.insert(key, candidate);
                    }
                    Some(current)
                        if current.lifecycle != candidate.lifecycle
                            || current.identity.address != candidate.identity.address =>
                    {
                        let candidate_after = observes(
                            &candidate.replica_id,
                            candidate.sequence,
                            &candidate.causal,
                            &current.replica_id,
                            current.sequence,
                        );
                        let current_after = observes(
                            &current.replica_id,
                            current.sequence,
                            &current.causal,
                            &candidate.replica_id,
                            candidate.sequence,
                        );
                        if candidate_after {
                            resources.insert(key, candidate);
                        } else if !current_after {
                            conflicts.insert(key.clone());
                            if (
                                current.sequence,
                                current.replica_id.as_str(),
                                current.event_id.as_str(),
                            ) < (
                                candidate.sequence,
                                candidate.replica_id.as_str(),
                                candidate.event_id.as_str(),
                            ) {
                                resources.insert(key, candidate);
                            }
                        }
                    }
                    Some(current)
                        if (
                            current.sequence,
                            current.replica_id.as_str(),
                            current.event_id.as_str(),
                        ) >= (
                            candidate.sequence,
                            candidate.replica_id.as_str(),
                            candidate.event_id.as_str(),
                        ) => {}
                    _ => {
                        resources.insert(key, candidate);
                    }
                }
            }
        }

        Ok(AliasJournalState {
            operations: operations.into_values().collect(),
            resources: resources.into_values().collect(),
            conflicts: conflicts.into_iter().collect(),
        })
    }
}

/// Latest deterministic state for one logical operation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReducedOperation {
    /// UUID v4 of the logical operation.
    pub operation_id: String,
    /// Provider-neutral operation category.
    pub operation: AliasOperationKind,
    /// Latest causally selected durable phase.
    pub phase: AliasOperationPhase,
    /// Stable target identity, when the operation has one.
    pub target: Option<AliasIdentity>,
    /// Desired or acknowledged lifecycle, when applicable.
    pub lifecycle: Option<AliasLifecycleState>,
    /// Stable failure category, when applicable.
    pub error: Option<AliasErrorCode>,
    sequence: u64,
    replica_id: String,
    event_id: String,
    causal: Vec<AliasCausalEntry>,
}

impl core::fmt::Debug for AliasReducedOperation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasReducedOperation([REDACTED])")
    }
}

impl AliasReducedOperation {
    fn from_event(event: &AliasJournalEvent) -> Self {
        Self {
            operation_id: event.operation_id.clone(),
            operation: event.operation,
            phase: event.phase,
            target: event.target.clone(),
            lifecycle: event.lifecycle,
            error: event.error,
            sequence: event.sequence,
            replica_id: event.replica_id.clone(),
            event_id: event.event_id.clone(),
            causal: event.causal.clone(),
        }
    }
}

/// Latest deterministic state for one connection-scoped alias resource.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasReducedResource {
    /// Stable connection-scoped identity and latest address snapshot.
    pub identity: AliasIdentity,
    /// Latest selected lifecycle state.
    pub lifecycle: AliasLifecycleState,
    /// Whether a deletion tombstone prevents resurrection.
    pub tombstoned: bool,
    sequence: u64,
    replica_id: String,
    event_id: String,
    causal: Vec<AliasCausalEntry>,
}

impl core::fmt::Debug for AliasReducedResource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasReducedResource([REDACTED])")
    }
}

/// Deterministic journal reduction returned to callers.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(Tsify),
    tsify(into_wasm_abi, from_wasm_abi, large_number_types_as_bigints)
)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasJournalState {
    /// Latest selected state for each logical operation.
    pub operations: Vec<AliasReducedOperation>,
    /// Latest selected state for each connection-scoped alias.
    pub resources: Vec<AliasReducedResource>,
    /// Operation IDs or resource keys whose concurrent terminal facts cannot be silently chosen.
    pub conflicts: Vec<String>,
}

impl core::fmt::Debug for AliasJournalState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AliasJournalState([REDACTED])")
    }
}

fn resource_key(identity: &AliasIdentity) -> String {
    format!("{}\n{}", identity.connection_id, identity.alias_id)
}

fn same_identity_snapshot(left: Option<&AliasIdentity>, right: Option<&AliasIdentity>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.resource_key() == right.resource_key() && left.address == right.address
        }
        (None, None) => true,
        _ => false,
    }
}

fn observes(
    observer_replica: &str,
    observer_sequence: u64,
    observer_causal: &[AliasCausalEntry],
    subject_replica: &str,
    subject_sequence: u64,
) -> bool {
    if observer_replica == subject_replica {
        return observer_sequence > subject_sequence;
    }
    observer_causal
        .iter()
        .any(|entry| entry.replica_id == subject_replica && entry.sequence >= subject_sequence)
}

const fn is_terminal(phase: AliasOperationPhase) -> bool {
    matches!(
        phase,
        AliasOperationPhase::Acknowledged
            | AliasOperationPhase::OutcomeUnknown
            | AliasOperationPhase::Failed
    )
}

fn validate_phase_progression(
    prior: &AliasJournalEvent,
    later: &AliasJournalEvent,
) -> Result<(), AliasError> {
    let allowed = match prior.phase {
        AliasOperationPhase::Prepared => true,
        AliasOperationPhase::Dispatched => later.phase != AliasOperationPhase::Prepared,
        AliasOperationPhase::OutcomeUnknown => matches!(
            later.phase,
            AliasOperationPhase::OutcomeUnknown
                | AliasOperationPhase::Acknowledged
                | AliasOperationPhase::Failed
        ),
        AliasOperationPhase::Acknowledged => later.phase == AliasOperationPhase::Acknowledged,
        AliasOperationPhase::Failed => later.phase == AliasOperationPhase::Failed,
    };
    let changed_terminal_fact = prior.phase == later.phase
        && is_terminal(prior.phase)
        && (prior.lifecycle != later.lifecycle || prior.error != later.error);
    if !allowed || changed_terminal_fact {
        return Err(AliasError::SyncConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_sensitive_value::SensitiveString;

    use super::*;

    fn event(event_id: &str, phase: AliasOperationPhase, sequence: u64) -> AliasJournalEvent {
        AliasJournalEvent {
            version: 1,
            event_id: event_id.to_owned(),
            operation_id: "123e4567-e89b-42d3-a456-426614174001".to_owned(),
            replica_id: "123e4567-e89b-42d3-a456-426614174002".to_owned(),
            sequence,
            causal: (sequence > 1)
                .then(|| AliasCausalEntry {
                    replica_id: "123e4567-e89b-42d3-a456-426614174002".to_owned(),
                    sequence: sequence - 1,
                })
                .into_iter()
                .collect(),
            operation: AliasOperationKind::Delete,
            phase,
            target: Some(
                AliasIdentity::new(
                    "123e4567-e89b-42d3-a456-426614174000".to_owned(),
                    "opaque/string:7".to_owned(),
                    SensitiveString::from("alias@example.com"),
                )
                .unwrap(),
            ),
            lifecycle: (phase == AliasOperationPhase::Acknowledged)
                .then_some(AliasLifecycleState::Deleted),
            error: (phase == AliasOperationPhase::OutcomeUnknown)
                .then_some(AliasErrorCode::OutcomeUnknown),
        }
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let dispatched = event(
            "123e4567-e89b-42d3-a456-426614174003",
            AliasOperationPhase::Dispatched,
            1,
        );
        let first = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![dispatched.clone()],
        };
        let second = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![
                dispatched,
                event(
                    "123e4567-e89b-42d3-a456-426614174004",
                    AliasOperationPhase::OutcomeUnknown,
                    2,
                ),
            ],
        };
        assert_eq!(first.merge(&second).unwrap(), second.merge(&first).unwrap());
        assert_eq!(
            first.merge(&first).unwrap(),
            first.clone().canonicalize().unwrap()
        );
        let third = AliasJournal::empty("123e4567-e89b-42d3-a456-426614174000".to_owned()).unwrap();
        assert_eq!(
            first.merge(&second).unwrap().merge(&third).unwrap(),
            first.merge(&second.merge(&third).unwrap()).unwrap()
        );
    }

    #[test]
    fn acknowledged_delete_is_a_non_resurrecting_tombstone() {
        let journal = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![event(
                "123e4567-e89b-42d3-a456-426614174005",
                AliasOperationPhase::Acknowledged,
                1,
            )],
        };
        let state = journal.reduce().unwrap();
        assert!(state.resources[0].tombstoned);
    }

    #[test]
    fn causally_ordered_lifecycle_changes_do_not_create_false_conflicts() {
        let mut enabled = event(
            "123e4567-e89b-42d3-a456-426614174006",
            AliasOperationPhase::Acknowledged,
            1,
        );
        enabled.operation_id = "123e4567-e89b-42d3-a456-426614174010".to_owned();
        enabled.operation = AliasOperationKind::Enable;
        enabled.lifecycle = Some(AliasLifecycleState::Enabled);
        let mut disabled = event(
            "123e4567-e89b-42d3-a456-426614174007",
            AliasOperationPhase::Acknowledged,
            2,
        );
        disabled.operation_id = "123e4567-e89b-42d3-a456-426614174011".to_owned();
        disabled.operation = AliasOperationKind::Disable;
        disabled.lifecycle = Some(AliasLifecycleState::Disabled);
        let state = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![disabled, enabled],
        }
        .reduce()
        .unwrap();
        assert!(state.conflicts.is_empty());
        assert_eq!(state.resources[0].lifecycle, AliasLifecycleState::Disabled);
    }

    #[test]
    fn concurrent_address_snapshots_for_one_resource_conflict() {
        let mut first = event(
            "123e4567-e89b-42d3-a456-426614174012",
            AliasOperationPhase::Acknowledged,
            1,
        );
        first.operation_id = "123e4567-e89b-42d3-a456-426614174013".to_owned();
        first.operation = AliasOperationKind::Enable;
        first.lifecycle = Some(AliasLifecycleState::Enabled);

        let mut second = first.clone();
        second.event_id = "123e4567-e89b-42d3-a456-426614174014".to_owned();
        second.operation_id = "123e4567-e89b-42d3-a456-426614174015".to_owned();
        second.replica_id = "123e4567-e89b-42d3-a456-426614174016".to_owned();
        second.target.as_mut().unwrap().address = SensitiveString::from("changed@example.com");

        let state = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![first, second],
        }
        .reduce()
        .unwrap();
        assert_eq!(state.conflicts.len(), 1);
    }

    #[test]
    fn non_lifecycle_operations_cannot_manufacture_resource_state() {
        let mut malicious = event(
            "123e4567-e89b-42d3-a456-426614174017",
            AliasOperationPhase::Acknowledged,
            1,
        );
        malicious.operation_id = "123e4567-e89b-42d3-a456-426614174018".to_owned();
        malicious.operation = AliasOperationKind::CreateSendReplyIdentity;
        malicious.lifecycle = Some(AliasLifecycleState::Deleted);

        assert!(matches!(
            malicious.validate(),
            Err(AliasError::InvalidInput)
        ));
    }

    #[test]
    fn one_operation_id_cannot_change_target_identity() {
        let first = event(
            "123e4567-e89b-42d3-a456-426614174019",
            AliasOperationPhase::Acknowledged,
            1,
        );
        let mut second = first.clone();
        second.event_id = "123e4567-e89b-42d3-a456-426614174020".to_owned();
        second.replica_id = "123e4567-e89b-42d3-a456-426614174021".to_owned();
        second.sequence = 1;
        second.causal.clear();
        second.target.as_mut().unwrap().alias_id = "different-resource".to_owned();

        let journal = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![first, second],
        };
        assert!(matches!(
            journal.canonicalize(),
            Err(AliasError::SyncConflict)
        ));
    }

    #[test]
    fn create_operation_cannot_rebind_after_first_acknowledged_target() {
        let mut prepared = event(
            "123e4567-e89b-42d3-a456-426614174022",
            AliasOperationPhase::Prepared,
            1,
        );
        prepared.operation = AliasOperationKind::Create;
        prepared.target = None;
        prepared.lifecycle = None;

        let mut acknowledged = event(
            "123e4567-e89b-42d3-a456-426614174023",
            AliasOperationPhase::Acknowledged,
            2,
        );
        acknowledged.operation = AliasOperationKind::Create;
        acknowledged.lifecycle = Some(AliasLifecycleState::Enabled);

        let mut rebound = acknowledged.clone();
        rebound.event_id = "123e4567-e89b-42d3-a456-426614174024".to_owned();
        rebound.sequence = 3;
        rebound.causal[0].sequence = 2;
        rebound.target.as_mut().unwrap().alias_id = "different-resource".to_owned();

        let journal = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![prepared, acknowledged, rebound],
        };
        assert!(matches!(
            journal.canonicalize(),
            Err(AliasError::SyncConflict)
        ));
    }

    #[test]
    fn causally_later_operation_phase_cannot_regress() {
        let acknowledged = event(
            "123e4567-e89b-42d3-a456-426614174025",
            AliasOperationPhase::Acknowledged,
            1,
        );
        let mut regressed = event(
            "123e4567-e89b-42d3-a456-426614174026",
            AliasOperationPhase::Prepared,
            2,
        );
        regressed.lifecycle = None;

        let journal = AliasJournal {
            version: 1,
            connection_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            events: vec![acknowledged, regressed],
        };
        assert!(matches!(
            journal.canonicalize(),
            Err(AliasError::SyncConflict)
        ));
    }
}
