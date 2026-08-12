"""Sanitized Tier 1 domain failures."""


class Tier1Error(Exception):
    """Base class for inert Tier 1 framework failures."""


class CanonicalizationError(Tier1Error):
    """A value cannot be represented by the canonical contract format."""


class ContractValidationError(Tier1Error):
    """A contract record is structurally invalid."""


class ContractNotFoundError(Tier1Error):
    """The requested authoritative contract does not exist."""


class ContractIntegrityError(Tier1Error):
    """A stored contract failed integrity verification."""


class ContractConflictError(Tier1Error):
    """An atomic state, idempotency, or target reservation conflict occurred."""


class IllegalTransitionError(Tier1Error):
    """The requested recovery state transition is not legal."""


class MutationPolicyError(Tier1Error):
    """The exact capability, endpoint, or method is not authorized."""


class ContractBindingError(Tier1Error):
    """An execution request does not match the authoritative contract."""


class ConfirmationError(Tier1Error):
    """Owner confirmation evidence is missing, invalid, or unverified."""


class KeyMaterialError(Tier1Error):
    """Key material could not be loaded safely."""


class KeyExhaustedError(Tier1Error):
    """A key's nonce counter has reached its retirement threshold."""


class ArtifactDecryptionError(Tier1Error):
    """A protected artifact failed authenticated decryption."""


class AnchorUnavailableError(Tier1Error):
    """The configured anti-rollback anchor could not be reached."""


class AnchorConflictError(Tier1Error):
    """The anti-rollback anchor's actual value did not match the expected one."""


class AnchorAlreadyProvisionedError(Tier1Error):
    """A one-time anchor provisioning operation (baseline seed or
    completion marker) was attempted against a store that already has
    one recorded -- refused, never silently overwritten."""


class WholeStoreRollbackDetected(Tier1Error):
    """The anti-rollback anchor is behind the store's recorded high-water mark."""


class Tier1ConfigurationError(Tier1Error):
    """Production Tier 1 store configuration is missing, partial, or unsafe."""


class RateLimitExceededError(Tier1Error):
    """A capability/target/global rate or blast-radius limit would be exceeded."""


class AuthorizationConsumptionError(Tier1Error):
    """A PlanAuthorization consumption record could not be safely
    written or read -- e.g. a malformed authorization_id, an unsafe
    store path, or a stored consumption row that failed integrity
    verification. Never raised for an ordinary, honest replay attempt
    (see AuthorizationConsumptionStore.try_consume(), which returns
    False for that case instead)."""


class PreparedExecutionIntentError(Tier1Error):
    """A prepared execution intent is structurally invalid or unsupported."""


class BoundExecutionError(Tier1Error):
    """The closed first-WRITE authorization/contract binding was refused."""
