package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.autopilot.AutonomyLevel
import org.xsecurity.scanner.autopilot.AutoPilotHealthScore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.autopilot.AutopilotPermission
import org.xsecurity.scanner.data.AppStorageSnapshot
import org.xsecurity.scanner.data.AppStorageUsage
import org.xsecurity.scanner.data.UpdateSettings

/** Updates, AutoPilot policy, health and special-access rationale entry points. */
@Composable
fun SettingsScreen(
    settings: UpdateSettings,
    versionName: String,
    versionCode: Long,
    autonomyLevel: AutonomyLevel,
    healthScore: AutoPilotHealthScore,
    quarantineCount: Int,
    capabilityStates: Map<AutopilotPermission, Boolean>,
    onAutoCheckChange: (Boolean) -> Unit,
    onMeteredChange: (Boolean) -> Unit,
    onAutonomyChange: (AutonomyLevel) -> Unit,
    onOpenQuarantine: () -> Unit,
    onRequestPermission: (AutopilotPermission) -> Unit,
    onBack: () -> Unit
) {
    val appContext = LocalContext.current.applicationContext
    var storageRefresh by remember { mutableStateOf(0) }
    var storageSnapshot by remember { mutableStateOf<AppStorageSnapshot?>(null) }
    LaunchedEffect(appContext, storageRefresh) {
        storageSnapshot = try {
            withContext(Dispatchers.IO) { AppStorageUsage.measure(appContext) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                    contentDescription = stringResource(R.string.history_back),
                    modifier = Modifier.size(28.dp)
                )
            }
            Text(
                text = stringResource(R.string.settings_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(stringResource(R.string.autopilot_settings_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.autopilot_settings_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    AutonomyLevel.values().forEach { level ->
                        FilterChip(
                            selected = autonomyLevel == level,
                            onClick = { onAutonomyChange(level) },
                            label = {
                                Text(
                                    when (level) {
                                        AutonomyLevel.L0 -> stringResource(R.string.autopilot_level_l0)
                                        AutonomyLevel.L1 -> stringResource(R.string.autopilot_level_l1)
                                        AutonomyLevel.L2 -> stringResource(R.string.autopilot_level_l2)
                                    }
                                )
                            }
                        )
                    }
                }
                Text(
                    text = stringResource(
                        when (autonomyLevel) {
                            AutonomyLevel.L0 -> R.string.autopilot_level_desc_l0
                            AutonomyLevel.L1 -> R.string.autopilot_level_desc_l1
                            AutonomyLevel.L2 -> R.string.autopilot_level_desc_l2
                        }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    stringResource(
                        R.string.autopilot_health_score,
                        healthScore.value,
                        when (healthScore.grade) {
                            AutoPilotHealthScore.Grade.GOOD -> stringResource(R.string.autopilot_health_good)
                            AutoPilotHealthScore.Grade.DEGRADED -> stringResource(R.string.autopilot_health_degraded)
                            AutoPilotHealthScore.Grade.LIMITED -> stringResource(R.string.autopilot_health_limited)
                        }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                TextButton(onClick = onOpenQuarantine, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.quarantine_history_open, quarantineCount))
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(stringResource(R.string.autopilot_permissions_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.autopilot_permissions_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                PermissionRow(
                    title = stringResource(R.string.autopilot_permission_battery),
                    description = stringResource(R.string.autopilot_permission_battery_desc),
                    granted = capabilityStates[AutopilotPermission.BATTERY_EXEMPTION] == true,
                    onOpen = { onRequestPermission(AutopilotPermission.BATTERY_EXEMPTION) }
                )
                PermissionRow(
                    title = stringResource(R.string.autopilot_permission_overlay),
                    description = stringResource(R.string.autopilot_permission_overlay_desc),
                    granted = capabilityStates[AutopilotPermission.OVERLAY] == true,
                    onOpen = { onRequestPermission(AutopilotPermission.OVERLAY) }
                )
                PermissionRow(
                    title = stringResource(R.string.autopilot_permission_usage),
                    description = stringResource(R.string.autopilot_permission_usage_desc),
                    granted = capabilityStates[AutopilotPermission.USAGE_ACCESS] == true,
                    onOpen = { onRequestPermission(AutopilotPermission.USAGE_ACCESS) }
                )
                PermissionRow(
                    title = stringResource(R.string.autopilot_permission_accessibility),
                    description = stringResource(R.string.autopilot_permission_accessibility_desc),
                    granted = capabilityStates[AutopilotPermission.ACCESSIBILITY] == true,
                    onOpen = { onRequestPermission(AutopilotPermission.ACCESSIBILITY) }
                )
                PermissionRow(
                    title = stringResource(R.string.settings_all_files_access_title),
                    description = stringResource(
                        if (capabilityStates[AutopilotPermission.ALL_FILES_ACCESS] == true) R.string.settings_all_files_access_desc_granted
                        else R.string.settings_all_files_access_desc_missing
                    ),
                    granted = capabilityStates[AutopilotPermission.ALL_FILES_ACCESS] == true,
                    onOpen = { onRequestPermission(AutopilotPermission.ALL_FILES_ACCESS) }
                )
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_updates_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.settings_updates_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                SettingRow(
                    title = stringResource(R.string.settings_auto_check),
                    description = stringResource(R.string.settings_auto_check_desc),
                    checked = settings.autoCheckEnabled,
                    onCheckedChange = onAutoCheckChange
                )
                SettingRow(
                    title = stringResource(R.string.settings_metered),
                    description = stringResource(R.string.settings_metered_desc),
                    checked = settings.allowMetered,
                    onCheckedChange = onMeteredChange,
                    enabled = settings.autoCheckEnabled
                )
            }
        }

        StorageUsageCard(storageSnapshot, onRefresh = { storageRefresh += 1 })

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_about_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.settings_version, versionName, versionCode),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun StorageUsageCard(snapshot: AppStorageSnapshot?, onRefresh: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.settings_storage_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                stringResource(R.string.settings_storage_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (snapshot == null) {
                Text(stringResource(R.string.settings_storage_loading), style = MaterialTheme.typography.bodySmall)
            } else {
                StorageUsageRow(R.string.settings_storage_total, snapshot.totalBytes)
                StorageUsageRow(R.string.settings_storage_vault, snapshot.vaultBytes)
                StorageUsageRow(R.string.settings_storage_signatures, snapshot.signaturesBytes)
                StorageUsageRow(R.string.settings_storage_audit, snapshot.auditBytes)
                StorageUsageRow(R.string.settings_storage_cache, snapshot.cacheBytes)
                StorageUsageRow(R.string.settings_storage_other, snapshot.otherBytes)
            }
            TextButton(onClick = onRefresh) { Text(stringResource(R.string.settings_storage_refresh)) }
        }
    }
}

@Composable
private fun StorageUsageRow(labelRes: Int, bytes: Long) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            stringResource(labelRes),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall
        )
        Text(formatStorageBytes(bytes), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun formatStorageBytes(bytes: Long): String {
    val safeBytes = bytes.coerceAtLeast(0L)
    return when {
        safeBytes < 1024L -> stringResource(R.string.settings_storage_size_b, safeBytes)
        safeBytes < 1024L * 1024L ->
            stringResource(R.string.settings_storage_size_kb, safeBytes.toDouble() / 1024.0)
        safeBytes < 1024L * 1024L * 1024L ->
            stringResource(R.string.settings_storage_size_mb, safeBytes.toDouble() / (1024.0 * 1024.0))
        else ->
            stringResource(R.string.settings_storage_size_gb, safeBytes.toDouble() / (1024.0 * 1024.0 * 1024.0))
    }
}

@Composable
private fun PermissionRow(title: String, description: String, granted: Boolean, onOpen: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                text = stringResource(if (granted) R.string.autopilot_permission_granted else R.string.autopilot_permission_missing),
                style = MaterialTheme.typography.labelSmall,
                color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
            )
        }
        TextButton(onClick = onOpen) { Text(stringResource(R.string.autopilot_permission_open)) }
    }
}

@Composable
private fun SettingRow(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
    }
}
