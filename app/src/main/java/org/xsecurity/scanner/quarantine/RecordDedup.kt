package org.xsecurity.scanner.quarantine

/**
 * RECORD DEDUP (P0): the same bytes re-scanned from the same location are the SAME case.
 *
 * Identity is `sha256 + sourcePath` (when the path is known) or `sha256 + sourceUri`
 * otherwise. A re-scan of the same identity UPDATES the existing row — new timestamps and
 * state — instead of appending a second one. A different path with the same bytes stays a
 * separate metadata record: the user may hold the same file in two places, but both rows may
 * safely reference one verified encrypted blob. VaultCutEngine releases that blob only after the
 * last non-terminal record stops referencing it.
 *
 * A re-observation only ever (re-)stages the encrypted copy, so no user-action gate is
 * bypassed: the original is still removed solely by the explicit "Delete now" tap.
 */
object RecordDedup {

    /** Stable identity string for a file record, or null when it cannot be deduplicated. */
    fun identity(sha256: String?, sourcePath: String?, sourceUri: String?): String? {
        val hash = sha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        val path = sourcePath?.trim()?.takeIf { it.isNotEmpty() }
        if (path != null) return "$hash|path:$path"
        val uri = sourceUri?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return "$hash|uri:$uri"
    }

    /** True when [existing] is the same file case as the observation described by the arguments. */
    fun isSameCase(
        existing: QuarantineRecord,
        sha256: String?,
        sourcePath: String?,
        sourceUri: String?
    ): Boolean {
        if (!existing.isFileRecord) return false
        val observed = identity(sha256, sourcePath, sourceUri) ?: return false
        return identity(existing.sha256, existing.sourcePath, existing.sourceUri) == observed
    }

    /** Newest matching file record (stores order by `detected_at DESC`), if any. */
    fun findExisting(
        candidates: List<QuarantineRecord>,
        sha256: String?,
        sourcePath: String?,
        sourceUri: String?
    ): QuarantineRecord? = candidates.firstOrNull { isSameCase(it, sha256, sourcePath, sourceUri) }

    /**
     * Content-identical bytes may reuse an existing encrypted blob only while its record is
     * QUARANTINED. This includes installed-package APK backups and file records; their metadata
     * rows remain distinct, and reference-aware release keeps the shared blob alive as needed.
     */
    fun findReusableVaultRecord(candidates: List<QuarantineRecord>, sha256: String?): QuarantineRecord? {
        val hash = sha256?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return candidates.firstOrNull { candidate ->
            candidate.state == QuarantineState.QUARANTINED &&
                candidate.sha256?.equals(hash, ignoreCase = true) == true &&
                !candidate.vaultFileName.isNullOrBlank()
        }
    }

    /**
     * Update-in-place for a re-observation: a verified or deduplicated vault copy, new timestamps,
     * and QUARANTINED with the original (again) on the device. Null arguments keep previous values.
     */
    fun reobserved(
        existing: QuarantineRecord,
        sha256: String?,
        label: String?,
        engine: String?,
        sizeBytes: Long?,
        scanOrigin: String?,
        vaultFileName: String?,
        sourcePath: String?,
        sourceUri: String?,
        nowMillis: Long
    ): QuarantineRecord = existing.copy(
        label = label?.take(120)?.takeIf { it.isNotBlank() } ?: existing.label,
        sha256 = sha256 ?: existing.sha256,
        engine = engine?.takeIf { it.isNotBlank() } ?: existing.engine,
        sizeBytes = sizeBytes ?: existing.sizeBytes,
        scanOrigin = scanOrigin ?: existing.scanOrigin,
        vaultFileName = vaultFileName ?: existing.vaultFileName,
        sourcePath = sourcePath ?: existing.sourcePath,
        sourceUri = sourceUri ?: existing.sourceUri,
        verdict = "KNOWN_BAD",
        detectedAtMillis = nowMillis,
        updatedAtMillis = nowMillis,
        state = QuarantineState.QUARANTINED,
        failureCode = null,
        residue = OriginalResidue.ORIGINAL_PRESENT,
        cutResult = null
    )

    /** Re-observation that could not be backed up: retain the original and record the precise limit. */
    fun vaultQuotaExceeded(
        existing: QuarantineRecord,
        sha256: String?,
        label: String?,
        engine: String?,
        sizeBytes: Long?,
        scanOrigin: String?,
        sourcePath: String?,
        sourceUri: String?,
        failureCode: String,
        nowMillis: Long
    ): QuarantineRecord = existing.copy(
        label = label?.take(120)?.takeIf { it.isNotBlank() } ?: existing.label,
        sha256 = sha256 ?: existing.sha256,
        engine = engine?.takeIf { it.isNotBlank() } ?: existing.engine,
        sizeBytes = sizeBytes ?: existing.sizeBytes,
        scanOrigin = scanOrigin ?: existing.scanOrigin,
        vaultFileName = null,
        restoreInfo = "encrypted_file_vault_not_saved",
        sourcePath = sourcePath ?: existing.sourcePath,
        sourceUri = sourceUri ?: existing.sourceUri,
        verdict = "KNOWN_BAD",
        detectedAtMillis = nowMillis,
        updatedAtMillis = nowMillis,
        state = QuarantineState.VAULT_QUOTA_EXCEEDED,
        failureCode = failureCode,
        residue = OriginalResidue.ORIGINAL_PRESENT,
        cutResult = failureCode
    )
}
