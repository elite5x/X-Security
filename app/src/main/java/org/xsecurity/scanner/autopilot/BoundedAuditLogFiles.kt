package org.xsecurity.scanner.autopilot

import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets

/**
 * Bounded JSONL file rotation. The active file and its single backup are each capped at 5 MiB;
 * older records are discarded at rotation. No Android API is used so the policy is JVM-testable.
 */
internal class BoundedAuditLogFiles(
    private val directory: File,
    private val maxFileBytes: Long = MAX_FILE_BYTES
) {
    val activeFile: File get() = File(directory, FILE_NAME)
    val backupFile: File get() = File(directory, BACKUP_FILE_NAME)

    private val lock = Any()

    init {
        require(maxFileBytes in 2L..(Long.MAX_VALUE / 2L))
    }

    /** Appends one JSONL payload and fsyncs it; false means the caller must fail closed. */
    fun appendLine(line: String): Boolean = synchronized(lock) {
        try {
            if (!directory.isDirectory && !directory.mkdirs()) return@synchronized false
            // Enforce retention even when this incoming payload is invalid or too large.
            if (!deleteOlderBackups()) return@synchronized false
            // Older app versions had no bound. Keep only the newest whole lines before continuing.
            if (!trimToTailIfOversized(backupFile) || !trimToTailIfOversized(activeFile)) {
                return@synchronized false
            }
            if (line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0) return@synchronized false
            val bytes = (line + "\n").toByteArray(StandardCharsets.UTF_8)
            if (bytes.size.toLong() > maxFileBytes) return@synchronized false
            if (activeFile.isFile && activeFile.length() > maxFileBytes - bytes.size) {
                if (!rotateActive()) return@synchronized false
            }
            FileOutputStreamSync.append(activeFile, bytes)
            activeFile.length() <= maxFileBytes && totalBytes() <= maxFileBytes * 2L
        } catch (_: Exception) {
            false
        }
    }

    /** Oldest-to-newest valid raw lines from the retained backup and active file. */
    fun readLinesOldestFirst(): List<String> = synchronized(lock) {
        buildList {
            addAll(readTailLines(backupFile))
            addAll(readTailLines(activeFile))
        }
    }

    fun totalBytes(): Long = boundedAdd(
        if (activeFile.isFile) activeFile.length() else 0L,
        if (backupFile.isFile) backupFile.length() else 0L
    )

    private fun rotateActive(): Boolean {
        if (!activeFile.isFile) return true
        if (backupFile.exists() && !backupFile.delete()) return false
        return activeFile.renameTo(backupFile)
    }

    private fun deleteOlderBackups(): Boolean {
        val entries = directory.listFiles() ?: return false
        val older = entries.filter { it.isFile && OLDER_BACKUP_NAME.matches(it.name) }
        return older.all { !it.exists() || it.delete() || !it.exists() }
    }

    /** Trims an oversized legacy file in place, preserving complete lines from its tail. */
    private fun trimToTailIfOversized(file: File): Boolean {
        if (!file.isFile || file.length() <= maxFileBytes) return true
        return try {
            RandomAccessFile(file, "rw").use { access ->
                val originalLength = access.length()
                access.seek(originalLength - maxFileBytes)
                while (access.filePointer < originalLength && access.read() != NEWLINE_BYTE) Unit
                val copyFrom = access.filePointer
                if (copyFrom >= originalLength) {
                    access.setLength(0L)
                } else {
                    var readAt = copyFrom
                    var writeAt = 0L
                    val buffer = ByteArray(COPY_BUFFER_BYTES)
                    while (readAt < originalLength) {
                        access.seek(readAt)
                        val count = access.read(buffer, 0, minOf(buffer.size.toLong(), originalLength - readAt).toInt())
                        if (count <= 0) break
                        access.seek(writeAt)
                        access.write(buffer, 0, count)
                        readAt += count
                        writeAt += count
                    }
                    access.setLength(writeAt)
                }
                access.fd.sync()
            }
            file.length() <= maxFileBytes
        } catch (_: Exception) {
            false
        }
    }

    /** Reads no more than [maxFileBytes] from an oversized legacy log. */
    private fun readTailLines(file: File): List<String> {
        if (!file.isFile) return emptyList()
        return try {
            val length = file.length()
            val start = (length - maxFileBytes).coerceAtLeast(0L)
            FileInputStream(file).use { input ->
                input.channel.position(start)
                BufferedReader(InputStreamReader(input, StandardCharsets.UTF_8)).use { reader ->
                    if (start > 0L) reader.readLine() // discard the first partial line
                    buildList {
                        while (true) {
                            val line = reader.readLine() ?: break
                            add(line)
                        }
                    }
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun boundedAdd(first: Long, second: Long): Long =
        if (first > Long.MAX_VALUE - second) Long.MAX_VALUE else first + second

    private object FileOutputStreamSync {
        fun append(file: File, bytes: ByteArray) {
            java.io.FileOutputStream(file, true).use { stream ->
                stream.write(bytes)
                stream.fd.sync()
            }
        }
    }

    companion object {
        const val FILE_NAME = "autopilot-audit.jsonl"
        const val BACKUP_FILE_NAME = "autopilot-audit.1.jsonl"
        const val MAX_FILE_BYTES = 5L * 1024L * 1024L
        const val MAX_TOTAL_BYTES = MAX_FILE_BYTES * 2L
        private val OLDER_BACKUP_NAME = Regex("autopilot-audit\\.(?:[2-9]|[1-9][0-9]+)\\.jsonl")
        private const val NEWLINE_BYTE = 0x0A
        private const val COPY_BUFFER_BYTES = 16 * 1024
    }
}
