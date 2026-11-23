package org.xsecurity.scanner.quarantine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.xsecurity.scanner.autopilot.CapabilityProvider
import org.xsecurity.scanner.autopilot.SecuritySignal
import org.xsecurity.scanner.autopilot.SystemPackageSafelist
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.device.InstalledAppsSource
import java.io.File
import java.util.UUID

/** Creates a metadata record, encrypts an APK copy, then asks the capability provider for soft containment. */
object QuarantineCoordinator {
    fun quarantine(
        context: Context,
        packageName: String,
        signals: List<SecuritySignal>,
        capabilityProvider: CapabilityProvider,
        nowMillis: Long = System.currentTimeMillis()
    ): QuarantineRecord? = synchronized(VaultStagingLock) {
        if (packageName.isBlank() || SystemPackageSafelist.isSystemPackage(context, packageName)) return@synchronized null
        val app = InstalledAppsSource.loadOne(context, packageName)
        val label = app?.displayName ?: packageName
        val sourceApk = app?.apkPaths?.firstOrNull()?.let(::File)
        val installer = installerPackageName(context, packageName)
        val sourceHash = sourceApk?.takeIf { it.isFile }
            ?.let { runCatching { Digest.sha256Hex(it) }.getOrNull() }
        val reusable = sourceHash?.let { findReusableVaultRecord(context, it) }
        val reusableName = reusable?.vaultFileName
        val vaultEntry = when {
            reusableName != null && sourceHash != null -> FileVault.StoredFile(reusableName, sourceHash)
            sourceApk != null && sourceApk.isFile -> {
                val stored = runCatching { FileVault.store(context, sourceApk, "q-${UUID.randomUUID()}") }
                    .getOrNull()
                if (stored == null) {
                    null
                } else {
                    // A fallback digest (or an APK that changed between hashing and encryption)
                    // can still collapse onto a previously backed-up blob. Drop only our own new
                    // encrypted copy after the existing one has been verified.
                    val matchingName = findReusableVaultRecord(context, stored.sha256)?.vaultFileName
                    if (matchingName != null && matchingName != stored.fileName) {
                        FileVault.delete(context, stored.fileName)
                        FileVault.StoredFile(matchingName, stored.sha256)
                    } else {
                        stored
                    }
                }
            }
            else -> null
        }
        val sha256 = vaultEntry?.sha256 ?: sourceHash
        val engine = signals
            .filter { it.verdict == SecuritySignal.Verdict.KNOWN_BAD }
            .map { it.provider.name }
            .distinct()
            .sorted()
            .joinToString(",")
            .ifBlank { "unknown" }
        val restoreInfo = buildString {
            append("method=pending")
            append(";version=").append(app?.versionName ?: "unknown")
            append(";version_code=").append(app?.versionCode ?: 0L)
            append(";installer=").append(installer ?: "unknown")
            append(";encrypted_backup=").append(if (vaultEntry == null) "unavailable" else "available")
        }
        val record = QuarantineRepository.newRecord(
            packageName = packageName,
            label = label,
            sha256 = sha256,
            verdict = "KNOWN_BAD",
            engine = engine,
            nowMillis = nowMillis,
            vaultFileName = vaultEntry?.fileName,
            restoreInfo = restoreInfo
        )
        QuarantineRepository.insert(context, record)
        val pending = QuarantineRepository.transition(
            context,
            record.id,
            QuarantineState.PENDING,
            QuarantineActor.AUTOMATION,
            nowMillis
        )
        if (pending !is QuarantineTransitionResult.Accepted) return@synchronized QuarantineRepository.record(context, record.id)

        val result = capabilityProvider.quarantine(context, packageName, record.id)
        when (result.state) {
            QuarantineState.QUARANTINED -> {
                QuarantineRepository.transition(
                    context,
                    record.id,
                    QuarantineState.QUARANTINED,
                    QuarantineActor.AUTOMATION,
                    System.currentTimeMillis()
                )
                QuarantineRepository.updateRestoreInfo(
                    context,
                    record.id,
                    "method=${result.methodCode};encrypted_backup=${if (vaultEntry == null) "unavailable" else "available"}"
                )
            }
            QuarantineState.PENDING -> QuarantineRepository.updateRestoreInfo(
                context,
                record.id,
                "method=${result.methodCode};encrypted_backup=${if (vaultEntry == null) "unavailable" else "available"}"
            )
            QuarantineState.FAILED -> {
                QuarantineRepository.transition(
                    context,
                    record.id,
                    QuarantineState.FAILED,
                    QuarantineActor.AUTOMATION,
                    System.currentTimeMillis(),
                    result.failureCode ?: "rootless_action_failed"
                )
                QuarantineRepository.updateRestoreInfo(
                    context,
                    record.id,
                    "method=${result.methodCode};encrypted_backup=${if (vaultEntry == null) "unavailable" else "available"}"
                )
            }
            else -> {
                QuarantineRepository.transition(
                    context,
                    record.id,
                    QuarantineState.FAILED,
                    QuarantineActor.AUTOMATION,
                    System.currentTimeMillis(),
                    "invalid_quarantine_result"
                )
            }
        }
        QuarantineRepository.record(context, record.id)
    }

    private fun findReusableVaultRecord(context: Context, sha256: String): QuarantineRecord? {
        val candidates = QuarantineRepository.quarantinedVaultRecordsBySha256(context, sha256)
        return RecordDedup.findReusableVaultRecord(candidates, sha256)?.takeIf { candidate ->
            candidate.vaultFileName?.let { fileName ->
                FileVault.exists(context, fileName) && FileVault.verify(context, fileName, sha256)
            } == true
        }
    }

    private fun installerPackageName(context: Context, packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(packageName)
        }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    } catch (_: RuntimeException) {
        null
    }
}
