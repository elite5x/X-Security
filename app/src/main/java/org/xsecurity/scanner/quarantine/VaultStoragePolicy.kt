package org.xsecurity.scanner.quarantine

import java.io.IOException

/** Serializes hash lookup + store across all quarantine entry points, preventing duplicate blobs. */
internal object VaultStagingLock

/** Reasons a new encrypted vault copy was refused; the source file is never changed. */
enum class VaultQuotaViolation(val failureCode: String) {
    FILE_TOO_LARGE("vault_file_too_large"),
    VAULT_FULL("vault_quota_exceeded")
}

class VaultQuotaExceededException(val violation: VaultQuotaViolation) :
    IOException(violation.failureCode)

/** Pure quota math shared by FileVault and JVM tests. All limits use binary MiB. */
internal object VaultStoragePolicy {
    const val MAX_SINGLE_FILE_BYTES: Long = 100L * 1024L * 1024L
    const val MAX_VAULT_BYTES: Long = 512L * 1024L * 1024L

    /**
     * Returns the first exceeded limit for [nextPlainBytes] additional source bytes.
     * [usedVaultBytes] includes every existing file in the vault directory, including abandoned
     * partial `.tmp` files. [encryptedOverheadBytes] reserves the XSV header and GCM tag.
     */
    fun violation(
        usedVaultBytes: Long,
        plainBytesAlreadyWritten: Long,
        nextPlainBytes: Long,
        encryptedOverheadBytes: Long
    ): VaultQuotaViolation? {
        if (usedVaultBytes < 0L || plainBytesAlreadyWritten < 0L || nextPlainBytes < 0L || encryptedOverheadBytes < 0L) {
            return VaultQuotaViolation.VAULT_FULL
        }
        if (nextPlainBytes > MAX_SINGLE_FILE_BYTES ||
            plainBytesAlreadyWritten > MAX_SINGLE_FILE_BYTES - nextPlainBytes
        ) {
            return VaultQuotaViolation.FILE_TOO_LARGE
        }

        val newPlainBytes = plainBytesAlreadyWritten + nextPlainBytes
        if (encryptedOverheadBytes > MAX_VAULT_BYTES || newPlainBytes > MAX_VAULT_BYTES - encryptedOverheadBytes) {
            return VaultQuotaViolation.VAULT_FULL
        }
        val newEncryptedBytes = newPlainBytes + encryptedOverheadBytes
        if (usedVaultBytes > MAX_VAULT_BYTES - newEncryptedBytes) return VaultQuotaViolation.VAULT_FULL
        return null
    }

    fun preflightViolation(
        usedVaultBytes: Long,
        sourceBytes: Long,
        encryptedOverheadBytes: Long
    ): VaultQuotaViolation? = violation(
        usedVaultBytes = usedVaultBytes,
        plainBytesAlreadyWritten = 0L,
        nextPlainBytes = sourceBytes,
        encryptedOverheadBytes = encryptedOverheadBytes
    )
}
