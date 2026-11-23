package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VaultStoragePolicyTest {
    private val headerAndTagBytes = 33L // XSV magic + IV-length byte + 12-byte GCM IV + 16-byte tag

    @Test
    fun acceptsExactlyOneHundredMebibytesAndRejectsTheNextByte() {
        assertNull(
            VaultStoragePolicy.preflightViolation(
                usedVaultBytes = 0L,
                sourceBytes = VaultStoragePolicy.MAX_SINGLE_FILE_BYTES,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
        assertEquals(
            VaultQuotaViolation.FILE_TOO_LARGE,
            VaultStoragePolicy.preflightViolation(
                usedVaultBytes = 0L,
                sourceBytes = VaultStoragePolicy.MAX_SINGLE_FILE_BYTES + 1L,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
    }

    @Test
    fun refusesWhenProjectedEncryptedVaultWouldExceedFiveHundredTwelveMebibytes() {
        val remainingForPlaintext = VaultStoragePolicy.MAX_VAULT_BYTES - headerAndTagBytes - 1L
        assertNull(
            VaultStoragePolicy.preflightViolation(
                usedVaultBytes = remainingForPlaintext,
                sourceBytes = 1L,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
        assertEquals(
            VaultQuotaViolation.VAULT_FULL,
            VaultStoragePolicy.preflightViolation(
                usedVaultBytes = remainingForPlaintext + 1L,
                sourceBytes = 1L,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
    }

    @Test
    fun streamingCheckCatchesGrowthAfterTheInitialFileSizeCheck() {
        assertEquals(
            VaultQuotaViolation.FILE_TOO_LARGE,
            VaultStoragePolicy.violation(
                usedVaultBytes = 0L,
                plainBytesAlreadyWritten = VaultStoragePolicy.MAX_SINGLE_FILE_BYTES - 10L,
                nextPlainBytes = 11L,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
    }

    @Test
    fun existingOrphanBytesAreCountedTowardTheTotalLimit() {
        assertEquals(
            VaultQuotaViolation.VAULT_FULL,
            VaultStoragePolicy.preflightViolation(
                usedVaultBytes = VaultStoragePolicy.MAX_VAULT_BYTES,
                sourceBytes = 0L,
                encryptedOverheadBytes = headerAndTagBytes
            )
        )
    }
}
