namespace Ecliptix.Domain.Memberships.Failures;

public static class MasterKeyMessageKeys
{
    public const string InvalidThreshold = "master_key_invalid_threshold";
    public const string InvalidShareCount = "master_key_invalid_share_count";
    public const string InvalidKeyLength = "master_key_invalid_key_length";
    public const string InvalidKeyData = "master_key_invalid_key_data";
    public const string InvalidShareData = "master_key_invalid_share_data";
    public const string InvalidIdentifier = "master_key_invalid_identifier";
    public const string ShareValidationFailed = "master_key_share_validation_failed";

    public const string KeySplittingFailed = "master_key_splitting_failed";
    public const string KeyReconstructionFailed = "master_key_reconstruction_failed";
    public const string KeyDerivationFailed = "master_key_derivation_failed";

    public const string InsufficientShares = "master_key_insufficient_shares";
    public const string NoSharesProvided = "master_key_no_shares_provided";
    public const string DuplicateShareIndexes = "master_key_duplicate_share_indexes";
    public const string SharesAlreadyExist = "master_key_shares_already_exist";
    public const string SharesNotFound = "master_key_shares_not_found";

    public const string HmacKeyStorageFailed = "master_key_hmac_storage_failed";
    public const string HmacKeyMissing = "master_key_hmac_missing";
    public const string HmacKeyRetrievalFailed = "master_key_hmac_retrieval_failed";
    public const string HmacKeyRemovalFailed = "master_key_hmac_removal_failed";

    public const string AllocationFailed = "master_key_allocation_failed";
    public const string MemoryReadFailed = "master_key_memory_read_failed";
    public const string MemoryWriteFailed = "master_key_memory_write_failed";

    public const string MembershipNotFoundOrInactive = "master_key_membership_not_found_or_inactive";
    public const string DefaultAccountNotFound = "master_key_default_account_not_found";
    public const string CredentialsNotFound = "master_key_credentials_not_found";

    public const string DataAccess = "master_key_data_access_failed";
    public const string DatabaseError = "master_key_database_error";
    public const string Timeout = "master_key_operation_timeout";
    public const string InsertFailed = "master_key_insert_failed";
    public const string QueryFailed = "master_key_query_failed";
    public const string DeleteFailed = "master_key_delete_failed";

    public const string ValidationFailed = "master_key_validation_failed";
    public const string Generic = "master_key_error_generic";
}
