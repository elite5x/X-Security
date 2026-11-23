package org.xsecurity.scanner.autopilot

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class BoundedAuditLogFilesTest {
    private lateinit var directory: File

    @Before
    fun setUp() {
        directory = Files.createTempDirectory("xsec-audit-rotation").toFile()
    }

    @After
    fun tearDown() {
        directory.deleteRecursively()
    }

    @Test
    fun repeatedRotationKeepsOnlyOneBackupAndReadsOldestToNewest() {
        val store = BoundedAuditLogFiles(directory, maxFileBytes = 24L)

        assertTrue(store.appendLine("AAAAAAAAAA"))
        assertTrue(store.appendLine("BBBBBBBBBB"))
        assertTrue(store.appendLine("CCCCCCCCCC")) // rotates A/B into the backup
        assertTrue(store.appendLine("DDDDDDDDDD"))
        assertTrue(store.appendLine("EEEEEEEEEE")) // replaces the old backup with C/D

        assertEquals(listOf("CCCCCCCCCC", "DDDDDDDDDD", "EEEEEEEEEE"), store.readLinesOldestFirst())
        assertTrue(store.activeFile.length() <= 24L)
        assertTrue(store.backupFile.length() <= 24L)
        assertTrue(store.totalBytes() <= 48L)
        assertFalse(File(directory, "autopilot-audit.2.jsonl").exists())
    }

    @Test
    fun rejectsSingleLineLargerThanTheFileCap() {
        val store = BoundedAuditLogFiles(directory, maxFileBytes = 8L)

        assertFalse(store.appendLine("12345678")) // newline would exceed the cap
        assertFalse(store.activeFile.exists())
        assertEquals(0L, store.totalBytes())
    }

    @Test
    fun oversizedLegacyLogIsTrimmedToWholeTailLinesBeforeAppending() {
        val store = BoundedAuditLogFiles(directory, maxFileBytes = 32L)
        store.activeFile.writeText("old\n${"x".repeat(40)}\nrecent\n")

        assertTrue(store.appendLine("new"))

        assertTrue(store.activeFile.length() <= 32L)
        assertTrue(store.backupFile.length() <= 32L)
        assertTrue(store.totalBytes() <= 64L)
        assertEquals(listOf("recent", "new"), store.readLinesOldestFirst())
    }

    @Test
    fun appendDeletesOlderRotationGenerations() {
        val store = BoundedAuditLogFiles(directory, maxFileBytes = 32L)
        val olderBackup = File(directory, "autopilot-audit.2.jsonl").apply { writeText("old\n") }
        val muchOlderBackup = File(directory, "autopilot-audit.12.jsonl").apply { writeText("older\n") }

        assertTrue(store.appendLine("new"))

        assertFalse(olderBackup.exists())
        assertFalse(muchOlderBackup.exists())
        assertTrue(store.totalBytes() <= 64L)
    }

    @Test
    fun retentionCleanupStillRunsWhenTheIncomingLineIsRejected() {
        val store = BoundedAuditLogFiles(directory, maxFileBytes = 16L)
        store.activeFile.writeText("x\n".repeat(20))
        val oldGeneration = File(directory, "autopilot-audit.2.jsonl").apply { writeText("old\n") }

        assertFalse(store.appendLine("y".repeat(20)))

        assertTrue(store.activeFile.length() <= 16L)
        assertFalse(oldGeneration.exists())
        assertTrue(store.totalBytes() <= 32L)
    }

    @Test
    fun productionRetentionLimitsAreFiveAndTenMebibytes() {
        assertEquals(5L * 1024L * 1024L, AuditLog.MAX_FILE_BYTES)
        assertEquals(10L * 1024L * 1024L, AuditLog.MAX_TOTAL_BYTES)
    }
}
