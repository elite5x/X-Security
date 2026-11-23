package org.xsecurity.scanner.data

import android.content.Context
import org.xsecurity.scanner.autopilot.AuditLog
import org.xsecurity.scanner.quarantine.FileVault
import java.io.File

/** Point-in-time usage of the app's private internal and app-specific external storage. */
data class AppStorageSnapshot(
    val totalBytes: Long,
    val vaultBytes: Long,
    val signaturesBytes: Long,
    val auditBytes: Long,
    val cacheBytes: Long,
    val otherBytes: Long
)

object AppStorageUsage {
    fun measure(context: Context): AppStorageSnapshot {
        val appContext = context.applicationContext
        val totalInternal = directoryBytes(appContext.dataDir)
        val internalCache = directoryBytes(appContext.cacheDir)
        val externalCache = appContext.getExternalCacheDirs().filterNotNull().fold(0L) { total, file ->
            saturatedAdd(total, directoryBytes(file))
        }
        val cache = saturatedAdd(internalCache, externalCache)
        val vault = FileVault.storageBytes(appContext)
        val signatures = directoryBytes(File(appContext.filesDir, "signatures"))
        val auditFile = AuditLog.file(appContext)
        val audit = saturatedAdd(fileBytes(auditFile), fileBytes(AuditLog.rotatedFile(appContext)))
        val externalFiles = appContext.getExternalFilesDirs(null).filterNotNull().fold(0L) { total, file ->
            saturatedAdd(total, directoryBytes(file))
        }

        // dataDir already contains internal cache, signatures, vault and audit.
        val categorizedInternal = saturatedAdd(
            saturatedAdd(saturatedAdd(internalCache, vault), signatures),
            audit
        )
        val otherInternal = (totalInternal - categorizedInternal).coerceAtLeast(0L)
        val other = saturatedAdd(otherInternal, externalFiles)
        val total = saturatedAdd(saturatedAdd(totalInternal, externalFiles), externalCache)
        return AppStorageSnapshot(
            totalBytes = total,
            vaultBytes = vault,
            signaturesBytes = signatures,
            auditBytes = audit,
            cacheBytes = cache,
            otherBytes = other
        )
    }

    private fun directoryBytes(root: File): Long = runCatching {
        if (!root.exists()) return@runCatching 0L
        var total = 0L
        root.walkTopDown().forEach { file ->
            if (file.isFile) total = saturatedAdd(total, file.length())
        }
        total
    }.getOrDefault(0L)

    private fun fileBytes(file: File): Long = if (file.isFile) file.length().coerceAtLeast(0L) else 0L

    private fun saturatedAdd(first: Long, second: Long): Long =
        if (second > 0L && first > Long.MAX_VALUE - second) Long.MAX_VALUE else first + second
}
