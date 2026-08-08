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
